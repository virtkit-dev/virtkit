//! `vk run --detach`: run the build + boot in the foreground, then daemonize once the
//! guest is ready — so Ctrl-C/Ctrl-Z during the build reach it like any foreground job, but
//! on success the terminal is freed while the microVM keeps running in the background.
//!
//! The CLI runs on a multi-threaded Tokio runtime, and forking a live runtime is undefined
//! behavior — so the fork happens in `main()` *before* the runtime is built. The child does
//! the real run (build, boot, hold the VM) and signals readiness over a pipe once the guest
//! is up. It stays in the terminal's foreground process group while it builds and boots — so
//! Ctrl-C aborts it and Ctrl-Z suspends it directly, no terminal-signal forwarding needed —
//! and `setsid`s into its own session only at [`signal_ready`], detaching once the VM is up.
//! The foreground parent just relays the child's exit status until then.
//!
//! Deferring the `setsid` is what makes the job-control signals work: a new session cannot be
//! the controlling terminal's foreground group, so a child that detached at fork was an
//! orphaned group the kernel *discards* SIGTSTP for (Ctrl-Z did nothing) and that terminal
//! signals never reached. It also means only the child changes group at readiness — `setsid`
//! moves its caller, not the caller's children — so the VMM/switch/virtiofsd it spawns before
//! then get sessions of their own at spawn ([`crate::spawn::spawn_tied`], keyed on
//! [`is_child`]). Left in the foreground group, they would keep taking the terminal's
//! Ctrl-C/Ctrl-Z after the run detached: `vk dev` goes on working in that group, and so does
//! a script run without job control. So job control reaches the driver alone: Ctrl-Z suspends
//! it while the build's guests run on, and Ctrl-C ends it — through teardown once the run is
//! waiting on the guest ([`interrupt`]), by default before that, either way taking the
//! PDEATHSIG-tied helpers with it.
//!
//! The parent still relays one thing: an external SIGTERM aimed at the supervisor alone — a
//! `timeout` wrapper or process manager that signals the pid, not the group — is forwarded to
//! the child so an aborted build tears down instead of orphaning. Terminal Ctrl-C/Ctrl-Z reach
//! the child directly and need no relay.

use std::os::fd::RawFd;
use std::path::Path;
use std::process::ExitCode;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Write end of the readiness pipe, held by the detached child (`-1` = not detaching). Set
/// by [`fork`] in the child; consumed once by [`signal_ready`].
static READY_FD: AtomicI32 = AtomicI32::new(-1);
/// PID of the child the parent supervises, for the SIGTERM relay (`-1` = none). Terminal
/// signals reach the child directly through the shared foreground group; this relays only an
/// external SIGTERM aimed at the parent alone. Cleared once the child detaches or exits.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);
/// Set for good by [`fork`] in the child: this process is the `--detach` child, before and
/// after it detaches. Read by [`crate::spawn::spawn_tied`] and [`interrupt`].
static IS_CHILD: AtomicBool = AtomicBool::new(false);
/// Marks the parent released when the guest is ready to run the post-boot steps. Set by
/// `main` after [`fork`] returns and read by [`crate::dev::cli`]. An environment variable
/// would be inherited by editors, hooks and task commands and mistaken for their own state.
static AFTER_BOOT: AtomicBool = AtomicBool::new(false);

/// Say that this process is the one released by the fork (see [`AFTER_BOOT`]).
pub fn note_after_boot() {
    AFTER_BOOT.store(true, Ordering::Relaxed);
}

/// Is this the process the fork released once the guest was ready?
pub fn after_boot() -> bool {
    AFTER_BOOT.load(Ordering::Relaxed)
}

/// Is this the `--detach` child (see [`IS_CHILD`])?
pub fn is_child() -> bool {
    IS_CHILD.load(Ordering::Relaxed)
}

/// Wait for a Ctrl-C (SIGINT) in the `--detach` child; never resolves in any other process.
/// Until it detaches, the child shares the terminal's foreground group, so a Ctrl-C reaches it
/// as SIGINT and must tear the run down the way a SIGTERM does, rather than end it by default
/// and leave the guests to the VMM's parent-death signal. A foreground run keeps SIGINT's
/// default action: there, the helpers share the terminal's group and take the Ctrl-C too. If
/// the handler cannot be installed, wait forever and leave the default in place. Once
/// installed the handler stays, as SIGTERM's does: a second Ctrl-C during teardown is ignored.
pub async fn interrupt() {
    if !is_child() {
        return std::future::pending().await;
    }
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
        Ok(mut sig) => {
            sig.recv().await;
        }
        Err(_) => std::future::pending().await,
    }
}

/// This invocation's boot nonce, initialized before the fork so both processes share it.
/// The child includes it in its state-dir note; the parent rejects a different nonce as
/// an earlier run's leftover (see [`crate::dev::boot`]).
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
/// action (`vk --config x.toml dev up`) does not hide it, and `--help`/`--version` never
/// reach here at all — clap answers those and exits before the fork.
pub fn wants_detach(cmd: &crate::Cmd) -> bool {
    match cmd {
        // Parsed, so a `--detach` after `--` is the guest's own argument and not this flag.
        crate::Cmd::Run { detach, .. } => *detach,
        crate::Cmd::Dev(dev) => dev.boots(),
        _ => false,
    }
}

extern "C" fn forward_term(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // async-signal-safe: relay the abort to the child, which tears down and EOFs our pipe.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
}

/// Fork for `--detach`. The child keeps the readiness pipe and returns [`Forked::Child`] to
/// run normally, staying in the terminal's foreground process group until it detaches at
/// [`signal_ready`]. The parent blocks until the child reports readiness (→ exit 0, VM left
/// running) or the child exits first (→ mirror its status, so a build/boot failure surfaces
/// in the foreground). Both share the foreground group, so the terminal delivers Ctrl-C /
/// Ctrl-Z to the child directly and the parent reacts to them by default. A failed pipe/fork
/// degrades to a foreground run.
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
        // Keep the foreground group until `signal_ready` so Ctrl-C aborts and Ctrl-Z suspends
        // the build/boot. Keep the readiness writer and terminal stdout/stderr for progress.
        unsafe { libc::close(read_fd) };
        READY_FD.store(write_fd, Ordering::Relaxed);
        IS_CHILD.store(true, Ordering::Relaxed);
        return Forked::Child;
    }
    // Parent: supervise the child until it is ready or gone. It shares this process's
    // foreground group while it builds and boots, so the terminal delivers Ctrl-C / Ctrl-Z to
    // it directly and this process reacts to them by default: Ctrl-C ends both, Ctrl-Z suspends
    // both and `fg` resumes both. The only relay is SIGTERM — an external kill of this
    // supervisor alone, which `forward_term` passes to the child so the build is not orphaned.
    unsafe { libc::close(write_fd) };
    CHILD_PID.store(pid, Ordering::Relaxed);
    // SAFETY: still single-threaded (pre-runtime). No `SA_RESTART`, so the readiness `read`
    // returns EINTR to loop; no `SA_RESETHAND`, so a second SIGTERM keeps relaying.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_term as *const () as libc::sighandler_t;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    // Block until the child writes the readiness byte or closes the pipe (EOF on exit). A
    // Ctrl-Z stops this read and SIGCONT transparently resumes it; a relayed SIGTERM or a stray
    // EINTR just loops back to waiting for the child to react.
    let mut byte = [0u8; 1];
    let ready = loop {
        let n = unsafe { libc::read(read_fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break n == 1;
    };
    if ready {
        // Detached and running: a SIGTERM here now ends this process's own post-boot work
        // (`vk dev` steps) rather than tearing the VM down.
        stop_forwarding_term();
        eprintln!("virtkit: dev VM ready — detached (pid {pid}), still running in the background");
        return Forked::Parent {
            code: ExitCode::SUCCESS,
            ok: true,
        };
    }
    // The child is gone without signalling ready: mirror its exit status. Stop relaying first —
    // its pid can be reused the moment it is reaped.
    stop_forwarding_term();
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
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

/// Stop relaying SIGTERM to the child: forget its pid and restore SIGTERM's default action, so
/// once the child has detached (or exited) a SIGTERM here ends this process's own work instead.
fn stop_forwarding_term() {
    CHILD_PID.store(-1, Ordering::Relaxed);
    // SAFETY: still single-threaded — the Tokio runtime is built after `fork` returns.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// Called by the run path once the guest is up and about to enter its lifetime wait: in a
/// detached child, detach into a new session and redirect stdout/stderr to `log` (so
/// post-detach output does not spill into the terminal the parent hands back), then wake the
/// parent. A no-op otherwise.
pub fn signal_ready(log: Option<&Path>) {
    let fd = READY_FD.swap(-1, Ordering::Relaxed);
    if fd < 0 {
        return; // not a detached run
    }
    // The guest is up: leave the terminal's foreground group for our own session now, so the
    // freed terminal's hang-up never reaches the VM we hold — but only now, having stayed in
    // the foreground through the build/boot so Ctrl-C/Ctrl-Z reached it. Safe: a forked child
    // is never its own group's leader, so `setsid` succeeds. It moves this process alone: the
    // VMM/switch/virtiofsd already spawned left the terminal's group at spawn (`spawn_tied`)
    // and stay our PDEATHSIG-tied children.
    unsafe { libc::setsid() };
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

    /// What `main` decides on, for the argv given: the parse the fork reads.
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
        // A global flag of `vk` or of `vk dev`, before the action, must not hide it from
        // the scan that reads off the parse.
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
