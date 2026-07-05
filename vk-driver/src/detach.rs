//! `vk run --detach`: run the build + boot in the foreground, then daemonize once the
//! guest is ready — so a Ctrl-C during the build tears it down cleanly, but on success the
//! terminal is freed while the microVM keeps running in the background.
//!
//! The CLI runs on a multi-threaded Tokio runtime, and forking a live runtime is undefined
//! behavior — so the fork happens in `main()` *before* the runtime is built. The child does
//! the real run (build, boot, hold the VM) and signals readiness over a pipe once the guest
//! is up; the foreground parent relays the child's exit until then, forwarding Ctrl-C so an
//! aborted build tears the child down instead of orphaning it.

use std::os::fd::RawFd;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

/// Write end of the readiness pipe, held by the detached child (`-1` = not detaching). Set
/// by [`fork`] in the child; consumed once by [`signal_ready`].
static READY_FD: AtomicI32 = AtomicI32::new(-1);
/// PID of the child the foreground parent supervises — read by the signal forwarder.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);

/// Outcome of [`fork`].
pub enum Forked {
    /// Foreground parent: `main` should return this code (the child reported ready, exited
    /// first, or was aborted by a forwarded signal).
    Parent(ExitCode),
    /// The detached child: continue down the normal run path.
    Child,
}

/// Should this raw `run` invocation daemonize? True when `--detach` precedes the guest
/// command (`--`), so the guest's own args are never mistaken for the flag.
pub fn wants_detach(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some("run")
        && args
            .iter()
            .skip(2)
            .take_while(|a| a.as_str() != "--")
            .any(|a| a == "--detach")
}

extern "C" fn forward_signal(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // async-signal-safe: just relay the abort to the child.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
}

/// Fork for `--detach`. The child `setsid`s (so it outlives the terminal), keeps the
/// readiness pipe, and returns [`Forked::Child`] to run normally. The parent blocks until
/// the child reports readiness (→ exit 0, VM left running), the child exits first (→ mirror
/// its status, so a build/boot failure surfaces in the foreground), or a signal arrives (→
/// forwarded to the child, which aborts). A failed pipe/fork degrades to a foreground run.
pub fn fork() -> Forked {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: called from `main` before any thread or Tokio runtime exists.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Forked::Child;
    }
    let [read_fd, write_fd] = fds;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Forked::Child;
    }
    if pid == 0 {
        // Child: new session (immune to the terminal's SIGHUP once the parent exits); keep
        // the write end for the readiness signal. stdout/stderr still point at the terminal,
        // so build progress shows until `signal_ready` redirects them.
        unsafe {
            libc::setsid();
            libc::close(read_fd);
        }
        READY_FD.store(write_fd, Ordering::Relaxed);
        return Forked::Child;
    }
    // Parent: supervise the child until it is ready or gone.
    unsafe { libc::close(write_fd) };
    CHILD_PID.store(pid, Ordering::Relaxed);
    // Install via `sigaction` (not `signal`, whose reset-on-delivery semantics vary): no
    // `SA_RESTART` so the readiness `read` returns EINTR to re-forward, and no `SA_RESETHAND`
    // so a second Ctrl-C keeps forwarding. Safe: still single-threaded (pre-runtime).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_signal as *const () as libc::sighandler_t;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    // Block until the child writes the readiness byte or closes the pipe (EOF on exit).
    let mut byte = [0u8; 1];
    let ready = loop {
        let n = unsafe { libc::read(read_fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue; // a forwarded signal — keep waiting for the child to react
        }
        break n == 1;
    };
    if ready {
        eprintln!("virtkit: dev VM ready — detached (pid {pid}), still running in the background");
        return Forked::Parent(ExitCode::SUCCESS);
    }
    // The child is gone without signalling ready: mirror its exit status.
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) as u8
    } else if libc::WIFSIGNALED(status) {
        128u8.wrapping_add(libc::WTERMSIG(status) as u8)
    } else {
        1
    };
    Forked::Parent(ExitCode::from(code))
}

/// Called by the run path once the guest is up and about to enter its lifetime wait: in a
/// detached child, redirect stdout/stderr to `log` (so post-detach output does not spill
/// into the terminal the parent hands back) and wake the parent. A no-op otherwise.
pub fn signal_ready(log: Option<&Path>) {
    let fd = READY_FD.swap(-1, Ordering::Relaxed);
    if fd < 0 {
        return; // not a detached run
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // Point our stdout/stderr at the log (or discard) *before* waking the parent, so once
    // the parent returns to the shell nothing more lands on its terminal.
    let target = open_log(log);
    if target >= 0 {
        unsafe {
            libc::dup2(target, libc::STDOUT_FILENO);
            libc::dup2(target, libc::STDERR_FILENO);
            if target > libc::STDERR_FILENO {
                libc::close(target);
            }
        }
    }
    // Wake the parent. Retry the one-byte write past EINTR; if it still fails to land, the
    // parent falls back to observing EOF/exit status on this child, so this is best-effort.
    let byte = [1u8];
    loop {
        let n = unsafe { libc::write(fd, byte.as_ptr() as *const libc::c_void, 1) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    unsafe { libc::close(fd) };
}

/// Open the detach log for append (creating it), falling back to `/dev/null` when no path
/// is given or the open fails — the daemon must never keep writing to the freed terminal.
fn open_log(log: Option<&Path>) -> RawFd {
    use std::os::unix::ffi::OsStrExt;
    if let Some(c) = log.and_then(|p| std::ffi::CString::new(p.as_os_str().as_bytes()).ok()) {
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC,
                0o644,
            )
        };
        if fd >= 0 {
            return fd;
        }
    }
    unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) }
}

#[cfg(test)]
mod tests {
    use super::wants_detach;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detach_before_double_dash_is_honored() {
        assert!(wants_detach(&argv(&["vk", "run", "--detach"])));
        assert!(wants_detach(&argv(&[
            "vk", "run", "--detach", "--", "sleep", "1"
        ])));
        assert!(wants_detach(&argv(&[
            "vk", "run", "--ssh", "--detach", "--", "sh"
        ])));
    }

    #[test]
    fn detach_after_double_dash_is_a_guest_arg() {
        assert!(!wants_detach(&argv(&[
            "vk", "run", "--", "cmd", "--detach"
        ])));
        assert!(!wants_detach(&argv(&["vk", "run", "--", "--detach"])));
    }

    #[test]
    fn only_the_run_subcommand_detaches() {
        assert!(!wants_detach(&argv(&["vk", "build", "--detach"])));
        assert!(!wants_detach(&argv(&["vk", "run"])));
        assert!(!wants_detach(&argv(&["vk"])));
        assert!(!wants_detach(&argv(&[])));
    }
}
