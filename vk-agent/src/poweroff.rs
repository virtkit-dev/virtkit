//! `vk-agent poweroff` / `vk-agent reboot` — end or restart the guest cleanly. The host runs
//! these over the exec channel where it would otherwise kill the VMM outright, which for the
//! guest is a power cut: every filesystem loses what its page cache still held and is left
//! dirty on disk. What the command does depends on who is PID 1:
//!
//! - systemd gets its poweroff/reboot request ([`SIG_POWEROFF`]/[`SIG_REBOOT`]): units stop,
//!   filesystems unmount.
//! - `vk-agent init` gets the same signal: it terminates its service, then ends the machine
//!   with every filesystem frozen clean (`init`'s shutdown path).
//! - Anything else — an entrypoint holding PID 1 — has no shutdown of its own, so it is done
//!   from here: the other processes are terminated and given a moment to exit, then `sync`,
//!   freeze every writable disk filesystem, and end the machine. An init that exits along with
//!   its child (tini, a `sh -c` wrapper) ends the guest before the freeze — PID 1 exiting is a
//!   kernel panic — which leaves things as a kill would have.
//!
//! The command returns as soon as the shutdown is under way; the host waits for the VMM to
//! exit, and kills it after a grace period when it does not.
//!
//! Every guest now has ACPI (cloud-hypervisor always did; libkrun gained it), so a power-off
//! (ACPI S5) ends the VM and a reset (ACPI reset register) restarts it — which the host's VMM
//! keeper relaunches in place. See [`end_machine`].

use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// systemd's power-off request is kernel signal 38: `SIGRTMIN+4` with glibc's `SIGRTMIN` of
/// 34. This musl binary uses `SIGRTMIN` 35, so `libc::SIGRTMIN() + 4` would instead be
/// [`SIG_REBOOT`]. A musl-built systemd would use 39, but distributions ship glibc-built
/// systemd. `vk-agent init` handles 38 too, giving the host one request for either init.
pub const SIG_POWEROFF: libc::c_int = 38;

/// systemd's reboot request, `SIGRTMIN+5`. `vk-agent init` handles it too.
pub const SIG_REBOOT: libc::c_int = 39;

/// What the caller asked the guest to do.
#[derive(Clone, Copy)]
pub enum Action {
    PowerOff,
    Reboot,
}

impl Action {
    fn signal(self) -> libc::c_int {
        match self {
            Action::PowerOff => SIG_POWEROFF,
            Action::Reboot => SIG_REBOOT,
        }
    }
}

/// End the VM with `reboot(2)`: ACPI power-off (S5) ends it, ACPI reset restarts it (the host
/// keeper then relaunches the VM in place). Async-signal-safe, so `init` can call it from a
/// signal handler. Never returns.
pub(crate) fn end_machine(action: Action) -> ! {
    let cmd = match action {
        Action::PowerOff => libc::LINUX_REBOOT_CMD_POWER_OFF,
        Action::Reboot => libc::LINUX_REBOOT_CMD_RESTART,
    };
    // SAFETY: reboot(2) has no memory-safety preconditions.
    unsafe { libc::reboot(cmd) };
    // An accepted request never returns. Exit on failure so PID 1 triggers a visible kernel
    // panic rather than hanging.
    std::process::exit(1)
}

/// Grace period after SIGTERM without an init. It is shorter than `vk-agent init`'s 20
/// seconds because no init arranged an orderly stop for these processes.
const TERM_GRACE: Duration = Duration::from_secs(10);

/// CLI entry for `vk-agent poweroff` / `vk-agent reboot`. Returns the process exit code.
pub fn main(action: Action, args: &[String]) -> i32 {
    if !args.is_empty() {
        eprintln!("usage: vk-agent poweroff|reboot");
        return 2;
    }
    if pid1_is_systemd() || pid1_is_this_agent() {
        // SAFETY: plain kill(2).
        if unsafe { libc::kill(1, action.signal()) } != 0 {
            eprintln!(
                "shutdown: signalling PID 1: {}",
                std::io::Error::last_os_error()
            );
            return 1;
        }
        return 0;
    }
    // With no init to ask, detach shutdown so this command can report success. Collect its
    // ancestors now to spare the exec server relaying that status; after this command exits,
    // the child is reparented to PID 1 and can no longer discover them through `getppid`.
    let spare = ancestors();
    // A new session avoids the exec server's process-group kill when its client disconnects.
    // Closing stdio prevents the server from waiting on inherited pipes.
    // SAFETY: fork(2); the child only calls async-signal-safe functions before it is on its
    // own, and `shutdown_here` never returns.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("shutdown: fork: {}", std::io::Error::last_os_error());
            1
        }
        0 => {
            // SAFETY: raw syscalls on this process's own session and descriptors.
            unsafe {
                libc::setsid();
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
                if null >= 0 {
                    libc::dup2(null, 0);
                    libc::dup2(null, 1);
                    libc::dup2(null, 2);
                    libc::close(null);
                }
            }
            shutdown_here(action, &spare)
        }
        _ => 0,
    }
}

/// Apply systemd's `sd_booted()` test, then check comm for early boot.
fn pid1_is_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
        || std::fs::read_to_string("/proc/1/comm").is_ok_and(|c| c.trim() == "systemd")
}

/// Whether PID 1 is this binary (`vk-agent init`). Compare inode identity because initramfs
/// `/init` and `/proc/self/exe` can name the same file differently or not at all after pivot.
fn pid1_is_this_agent() -> bool {
    match (
        std::fs::metadata("/proc/1/exe"),
        std::fs::metadata("/proc/self/exe"),
    ) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// This process and its ancestors through PID 1, nearest first. Stop on unreadable status or
/// after 64 entries so a corrupt parent chain cannot loop.
fn ancestors() -> Vec<libc::pid_t> {
    // SAFETY: getpid(2).
    let mut pid = unsafe { libc::getpid() };
    let mut chain = Vec::new();
    while pid > 1 && chain.len() < 64 {
        chain.push(pid);
        match proc_status(pid) {
            Some((ppid, _)) => pid = ppid,
            None => break,
        }
    }
    chain.push(1);
    chain
}

/// Terminate every process except `spare` and this one, wait up to [`TERM_GRACE`], sync and
/// freeze filesystems, then end the machine. Never returns.
fn shutdown_here(action: Action, spare: &[libc::pid_t]) -> ! {
    // SAFETY: getpid(2).
    let me = unsafe { libc::getpid() };
    let spare: Vec<libc::pid_t> = spare.iter().copied().chain([me]).collect();
    for pid in user_pids(&spare) {
        // SAFETY: plain kill(2); a process gone meanwhile is an ESRCH we ignore.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline && !user_pids(&spare).is_empty() {
        std::thread::sleep(Duration::from_millis(100));
    }
    // SAFETY: sync(2).
    unsafe { libc::sync() };
    for mnt in writable_disk_mounts() {
        crate::fsfreeze::freeze_for_poweroff(&mnt);
    }
    crate::fsfreeze::freeze_for_poweroff(c"/");
    end_machine(action)
}

/// Live userspace processes except `spare`. Exclude PID 2, its kernel-thread children, and
/// zombies; an init that does not reap would otherwise make every wait exhaust the grace.
fn user_pids(spare: &[libc::pid_t]) -> Vec<libc::pid_t> {
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    procs
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter(|pid| *pid != 2 && !spare.contains(pid))
        .filter(|pid| proc_status(*pid).is_some_and(|(ppid, state)| ppid != 2 && state != 'Z'))
        .collect()
}

/// Read a process's parent and one-letter state (`R`, `S`, `Z`, …), or `None` once it is gone.
/// Parse bytes because a truncated multibyte comm can make `Name:` invalid UTF-8.
fn proc_status(pid: libc::pid_t) -> Option<(libc::pid_t, char)> {
    parse_status(&std::fs::read(format!("/proc/{pid}/status")).ok()?)
}

fn parse_status(status: &[u8]) -> Option<(libc::pid_t, char)> {
    let field = |name: &[u8]| {
        status
            .split(|b| *b == b'\n')
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim_ascii())
    };
    let ppid = std::str::from_utf8(field(b"PPid:")?).ok()?.parse().ok()?;
    let state = char::from(*field(b"State:")?.first()?);
    Some((ppid, state))
}

/// Writable block-device mount points other than root from `/proc/self/mounts`. Freeze root
/// separately and last.
fn writable_disk_mounts() -> Vec<CString> {
    let Ok(mounts) = std::fs::read("/proc/self/mounts") else {
        return Vec::new();
    };
    writable_disk_mounts_in(&mounts)
}

fn writable_disk_mounts_in(mounts: &[u8]) -> Vec<CString> {
    mounts
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let mut f = line.split(|b| *b == b' ').filter(|f| !f.is_empty());
            let (src, mnt, _fstype, opts) = (f.next()?, f.next()?, f.next()?, f.next()?);
            (src.starts_with(b"/dev/")
                && mnt != b"/"
                && opts.split(|b| *b == b',').any(|o| o == b"rw"))
            .then(|| CString::new(unescape_mount_field(mnt)).ok())
            .flatten()
        })
        .collect()
}

/// Decode `/proc/self/mounts` escapes for space, tab, newline, and backslash. Preserve other
/// backslash sequences.
fn unescape_mount_field(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&b, tail)) = rest.split_first() {
        rest = tail;
        if b != b'\\' {
            out.push(b);
            continue;
        }
        let octal = tail.get(..3).and_then(|digits| {
            digits.iter().try_fold(0u32, |acc, d| {
                (b'0'..=b'7')
                    .contains(d)
                    .then(|| acc * 8 + u32::from(d - b'0'))
            })
        });
        match octal.and_then(|v| u8::try_from(v).ok()) {
            Some(v) => {
                out.push(v);
                rest = tail.get(3..).unwrap_or_default();
            }
            None => out.push(b'\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_error_on_arguments() {
        assert_eq!(main(Action::PowerOff, &["now".to_string()]), 2);
        assert_eq!(main(Action::Reboot, &["now".to_string()]), 2);
    }

    #[test]
    fn action_maps_to_its_pid1_signal() {
        assert_eq!(Action::PowerOff.signal(), SIG_POWEROFF);
        assert_eq!(Action::Reboot.signal(), SIG_REBOOT);
    }

    #[test]
    fn pid1_is_not_this_test_runner() {
        // The test runner is not PID 1; inode comparison must return false without error.
        assert!(!pid1_is_this_agent());
    }

    #[test]
    fn ancestors_start_at_this_process_and_end_at_pid1() {
        let chain = ancestors();
        // SAFETY: getpid(2).
        assert_eq!(chain.first(), Some(&unsafe { libc::getpid() }));
        assert_eq!(chain.last(), Some(&1));
    }

    #[test]
    fn user_pids_spares_what_it_is_told_to() {
        // SAFETY: getpid(2).
        let me = unsafe { libc::getpid() };
        assert!(user_pids(&[]).contains(&me));
        assert!(!user_pids(&[me]).contains(&me));
    }

    #[test]
    fn parse_status_reads_parent_and_state() {
        let status =
            b"Name:\tsleep\nUmask:\t0022\nState:\tZ (zombie)\nTgid:\t42\nPid:\t42\nPPid:\t7\n";
        assert_eq!(parse_status(status), Some((7, 'Z')));
        // Parse fields even when TASK_COMM_LEN truncates comm mid-character.
        assert_eq!(
            parse_status(b"Name:\tcaf\xc3\nState:\tS (sleeping)\nPPid:\t12\n"),
            Some((12, 'S'))
        );
        assert_eq!(parse_status(b"Name:\tx\nPPid:\t1\n"), None);
        assert_eq!(parse_status(b"State:\tS (sleeping)\n"), None);
    }

    #[test]
    fn writable_disk_mounts_keeps_rw_block_devices_but_the_root() {
        let mounts = b"/dev/vda / ext4 rw,relatime 0 0\n\
            proc /proc proc rw,nosuid 0 0\n\
            /dev/vdb /data ext4 rw,nosuid,nodev 0 0\n\
            /dev/vdc /ro ext4 ro,relatime 0 0\n\
            tmpfs /tmp tmpfs rw 0 0\n\
            /dev/vdd /with\\040space ext4 rw 0 0\n\
            /dev/vde /cache ext4 rw 0 0\n";
        let got = writable_disk_mounts_in(mounts);
        assert_eq!(got, [c"/data", c"/with space", c"/cache"]);
    }

    #[test]
    fn unescape_mount_field_decodes_octal_only() {
        assert_eq!(unescape_mount_field(b"/a\\040b\\011c"), b"/a b\tc");
        assert_eq!(unescape_mount_field(b"/a\\134b"), b"/a\\b");
        // Preserve non-octal and truncated escapes.
        assert_eq!(unescape_mount_field(b"/a\\x\\04"), b"/a\\x\\04");
        assert_eq!(unescape_mount_field(b"/a\\999"), b"/a\\999");
    }
}
