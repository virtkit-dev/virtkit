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
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Write end of the readiness pipe, held by the detached child (`-1` = not detaching). Set
/// by [`fork`] in the child; consumed once by [`signal_ready`].
static READY_FD: AtomicI32 = AtomicI32::new(-1);
/// PID of the child the foreground parent supervises — read by the signal forwarder.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);
/// Whether this process is the parent the fork released once the guest was ready, and so
/// the side that does the work *around* the boot. Set by `main` after [`fork`] returns and
/// read by [`crate::dev::cli`]; deliberately not an environment variable, which every
/// process `vk dev` then spawns — the editor, a hook, a task's command — would inherit and
/// mistake for its own.
static AFTER_BOOT: AtomicBool = AtomicBool::new(false);

/// Say that this process is the one released by the fork (see [`AFTER_BOOT`]).
pub fn note_after_boot() {
    AFTER_BOOT.store(true, Ordering::Relaxed);
}

/// Is this the process the fork released once the guest was ready?
pub fn after_boot() -> bool {
    AFTER_BOOT.load(Ordering::Relaxed)
}

/// This invocation's boot nonce. Initialized before the fork, so the child inherits the
/// value in its copy of this memory and the two sides recognize each other's writing: the
/// child stamps it into the note it leaves in the state dir, and the parent reads a note
/// carrying any other nonce as an earlier run's leftovers rather than as this boot's
/// (see [`crate::dev::boot`]).
pub fn boot_nonce() -> &'static str {
    static BOOT_NONCE: OnceLock<String> = OnceLock::new();
    BOOT_NONCE.get_or_init(nonce)
}

/// A token no other invocation has: 16 bytes of `/dev/urandom`, hex — the clock and this
/// pid where that cannot be read. What matters is that two runs differ, not that it is
/// unguessable.
fn nonce() -> String {
    use std::io::Read;

    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
    {
        return bytes.iter().map(|b| format!("{b:02x}")).collect();
    }
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{since_epoch}-{}", std::process::id())
}

/// Outcome of [`fork`].
pub enum Forked {
    /// Foreground parent: the child reported ready, exited first, or was aborted by a
    /// forwarded signal.
    Parent {
        /// what `main` should return
        code: ExitCode,
        /// whether the child got as far as it meant to — ready, or exited successfully.
        /// `vk dev` does the steps *around* the boot here, and only when the boot worked.
        ok: bool,
    },
    /// The detached child: continue down the normal run path.
    Child,
}

/// Should this invocation daemonize? True for `vk run --detach`, and for the `vk dev`
/// actions that boot the environment and so leave it running behind them.
///
/// Decided on the parsed command line rather than on raw argv: a global flag before the
/// action (`vk --config x.toml dev up`) no longer hides it, and `--help`/`--version` never
/// reach here at all — clap answers those and exits before the fork.
pub fn wants_detach(cmd: &crate::Cmd) -> bool {
    match cmd {
        // Parsed, so a `--detach` after `--` is the guest's own argument and not this flag.
        crate::Cmd::Run { detach, .. } => *detach,
        crate::Cmd::Dev(dev) => dev.boots(),
        _ => false,
    }
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
    // Before the fork, so both sides end up with the same value in their own memory.
    let _ = boot_nonce();
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
        // Supervision is over: `vk dev` goes on to do the work *around* the boot in this
        // process, and until this is undone a Ctrl-C there would be swallowed and sent to
        // the child holding the VM — tearing the environment down instead of the command.
        release_child();
        eprintln!("virtkit: dev VM ready — detached (pid {pid}), still running in the background");
        return Forked::Parent {
            code: ExitCode::SUCCESS,
            ok: true,
        };
    }
    // The child is gone without signalling ready: mirror its exit status.
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    // Reaped, so its pid can be handed to something else at any moment: nothing may forward
    // a signal to it again.
    release_child();
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) as u8
    } else if libc::WIFSIGNALED(status) {
        128u8.wrapping_add(libc::WTERMSIG(status) as u8)
    } else {
        1
    };
    Forked::Parent {
        code: ExitCode::from(code),
        // A child that exited cleanly without signalling did its whole job — `vk dev up`
        // takes that path when the environment was already running.
        ok: code == 0,
    }
}

/// Stop supervising the child: forget its pid and put SIGINT/SIGTERM back to their default
/// action, so this process reacts to Ctrl-C as any other command does.
fn release_child() {
    CHILD_PID.store(-1, Ordering::Relaxed);
    // SAFETY: still single-threaded — the Tokio runtime is built after `fork` returns.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
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
    use clap::Parser;

    /// What `main` decides on, for the argv given: the parse is what the fork now reads.
    fn wants_detach(parts: &[&str]) -> bool {
        super::wants_detach(&crate::Cli::parse_from(parts).cmd)
    }

    #[test]
    fn detach_before_double_dash_is_honored() {
        assert!(wants_detach(&["vk", "run", "--detach"]));
        assert!(wants_detach(&["vk", "run", "--detach", "--", "sleep", "1"]));
        assert!(wants_detach(&[
            "vk", "run", "--ssh", "--detach", "--", "sh"
        ]));
    }

    #[test]
    fn detach_after_double_dash_is_a_guest_arg() {
        assert!(!wants_detach(&["vk", "run", "--", "cmd", "--detach"]));
        assert!(!wants_detach(&["vk", "run", "--", "--detach"]));
    }

    #[test]
    fn only_the_run_subcommand_detaches() {
        // No other command has the flag at all — clap refuses `vk build --detach` before
        // this is consulted — so what is left to check is that a plain `run` does not.
        assert!(!wants_detach(&["vk", "build"]));
        assert!(!wants_detach(&["vk", "run", "alpine"]));
    }

    #[test]
    fn a_dev_boot_detaches_behind_any_global_flag() {
        // The flags of `vk` itself and of `vk dev` used to hide the action from the scan
        // this now reads off the parse.
        assert!(wants_detach(&["vk", "dev", "shell"]));
        assert!(wants_detach(&["vk", "--config", "/x.toml", "dev", "shell"]));
        assert!(wants_detach(&[
            "vk",
            "dev",
            "--workspace",
            "/w",
            "--freshness",
            "reuse",
            "exec",
            "--",
            "ls"
        ]));
        // `--workspace up` names a directory, not the action.
        assert!(!wants_detach(&["vk", "dev", "--workspace", "up", "status"]));
    }
}
