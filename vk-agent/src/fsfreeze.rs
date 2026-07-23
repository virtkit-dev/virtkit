//! Freeze/thaw a mounted filesystem from inside the guest — the `FIFREEZE`/`FITHAW`
//! ioctls, the same thing util-linux `fsfreeze` does, built into the agent so it works
//! on guests without util-linux (e.g. busybox). The host invokes it over the existing
//! exec channel (`vk-agent fsfreeze -f|-u <mountpoint>`) to quiesce the root fs
//! for a consistent snapshot: a freeze flushes and checkpoints the journal and marks
//! the ext4 superblock clean on disk, so the snapshot needs no recovery.

use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result};

// _IOWR('X', 119/120, int) — architecture-independent (the size field is sizeof(int)).
// `libc::Ioctl` is c_ulong on glibc but c_int on musl, so write the value as u32 and
// reinterpret: zero-extends on glibc, same low 32 bits on musl.
const FIFREEZE: libc::Ioctl = 0xc004_5877_u32 as libc::Ioctl;
const FITHAW: libc::Ioctl = 0xc004_5878_u32 as libc::Ioctl;
// _IOWR('X', 121, struct fstrim_range) — sizeof(fstrim_range) == 24 (three u64).
const FITRIM: libc::Ioctl = 0xc018_5879_u32 as libc::Ioctl;

/// `struct fstrim_range` — the whole-fs discard request FITRIM takes. `len = u64::MAX`
/// means "to the end"; the kernel writes back the trimmed byte count in `len`.
#[repr(C)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

/// Discard the free blocks of the filesystem mounted at `path` (`FITRIM`, like util-linux
/// `fstrim`), so a subsequent snapshot's allocation map lists only live data — blocks freed
/// by files created and deleted since the last snapshot are released back to holes and never
/// enter the delta. Best-effort at the call site: a fs/backend without discard just keeps them.
pub fn trim(path: &Path) -> Result<()> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: `f` is a valid fd; FITRIM reads/writes a fstrim_range through the pointer.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), FITRIM, &raw mut range) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("FITRIM on {}", path.display()));
    }
    Ok(())
}

/// Freeze the filesystem mounted at `path` (writes block until [`thaw`]).
pub fn freeze(path: &Path) -> Result<()> {
    ioctl_fs(path, FIFREEZE, "FIFREEZE")
}

/// Thaw a filesystem previously [`freeze`]d.
pub fn thaw(path: &Path) -> Result<()> {
    ioctl_fs(path, FITHAW, "FITHAW")
}

/// Freeze the fs at `mountpoint` for an imminent power-off: FIFREEZE flushes and checkpoints
/// the ext4 journal and clears its needs-recovery flag on disk (the same "no recovery needed"
/// property the snapshot path relies on), so a journaled root — an OCI/docker-image boot —
/// mounts without journal recovery next time. Without it the next mount of a persisted or
/// checkpointed disk runs journal recovery.
///
/// Unlike [`freeze`], this is **async-signal-safe** (raw `open`/`ioctl`/`close`, a caller-owned
/// `'static` C path, no allocation and no `Result`) so [`crate::init`]'s `poweroff` can call it
/// from the `SIGTERM` handler. Best-effort — errors are ignored — and there is no thaw: the VM
/// is powering off, so the freeze need never be undone.
pub(crate) fn freeze_for_poweroff(mountpoint: &std::ffi::CStr) {
    // SAFETY: raw syscalls only. `mountpoint` is a valid NUL-terminated C string; FIFREEZE
    // ignores its third argument; a failed open yields fd < 0 and we skip the ioctl.
    unsafe {
        let fd = libc::open(mountpoint.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            libc::ioctl(fd, FIFREEZE, 0);
            libc::close(fd);
        }
    }
}

fn ioctl_fs(path: &Path, request: libc::Ioctl, name: &str) -> Result<()> {
    // The freeze lives on the superblock, not the fd, so it persists after this fd is
    // closed and the process exits — freeze and thaw can be separate invocations. A
    // read-only handle on the mount point suffices (util-linux opens O_RDONLY too).
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: `f` is a valid fd; FIFREEZE/FITHAW ignore the third argument.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), request, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("{name} on {}", path.display()));
    }
    Ok(())
}

/// CLI entry for `vk-agent fsfreeze -f|-u <mountpoint>` — mirrors util-linux
/// `fsfreeze`. Returns the process exit code.
pub fn main(args: &[String]) -> i32 {
    let (op, path): (fn(&Path) -> Result<()>, &str) = match args {
        [flag, path] if flag == "-f" => (freeze, path),
        [flag, path] if flag == "-u" => (thaw, path),
        _ => {
            eprintln!("usage: vk-agent fsfreeze -f|-u <mountpoint>");
            return 2;
        }
    };
    match op(Path::new(path)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("fsfreeze: {e:#}");
            1
        }
    }
}

/// CLI entry for `vk-agent fstrim <mountpoint>` — mirrors util-linux `fstrim`.
pub fn trim_main(args: &[String]) -> i32 {
    let [path] = args else {
        eprintln!("usage: vk-agent fstrim <mountpoint>");
        return 2;
    };
    match trim(Path::new(path)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("fstrim: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_for_poweroff_is_a_quiet_no_op_when_the_path_cannot_be_opened() {
        // Best-effort contract: if the mountpoint cannot even be opened, the helper must
        // return without panicking so poweroff() still proceeds to reboot(). A path that
        // cannot exist keeps the test hermetic — open() fails, so the FIFREEZE ioctl is never
        // issued and no real filesystem is ever touched (a test must never freeze a live fs).
        freeze_for_poweroff(c"/vk-agent-nonexistent-freeze-target");
    }
}
