//! Host side of `vk exec`: dial a running guest's agent exec channel and run a
//! command there, reusing the very client the embedded agent uses
//! (`vk_core::exec::client`). So a host that already has `vk` needs no separate
//! `vk-agent` binary to open a shell or run a command in a live VM — the same way
//! `vk status` replaced the agent's liveness probe.

use std::process::ExitCode;

use anyhow::{Result, bail};
use vk_core::addr::SocketAddr;
use vk_core::exec::client::{Stdin, client_run_cmd, client_run_tty};
use vk_core::messages::{CmdExec, CmdResult, RunMode, Tty};
use vk_core::net::connect;

/// Reject `--env` entries the server would silently drop: the guest keeps only
/// `KEY=value` pairs, so an entry without `=` is a user mistake, not a no-op.
fn check_env(env: &[String]) -> Result<()> {
    if let Some(bad) = env.iter().find(|e| !e.contains('=')) {
        bail!("invalid --env {bad:?} (expected KEY=value)");
    }
    Ok(())
}

/// Connect to `addr` and run `cmd`/`args` on the guest, streaming stdio (or a pty
/// when `tty`). Mirrors `vk-agent exec`: the same validation, tty negotiation, and
/// message flow, against the same shared client.
///
/// `stdin` selects the command's input. A process running multiple commands must pass
/// [`Stdin::Closed`]. TTY runs always consume this process's terminal and cannot use it.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    addr: SocketAddr,
    background: bool,
    clear_env: bool,
    env: Vec<String>,
    dir: Option<String>,
    tty: bool,
    user: Option<String>,
    cmd: String,
    args: Vec<String>,
    stdin: Stdin,
) -> Result<CmdResult> {
    check_env(&env)?;
    // Check before negotiation so non-terminal callers see this error first.
    if tty && stdin == Stdin::Closed {
        bail!("--tty always reads this process's stdin");
    }
    let mode = if background {
        RunMode::Background
    } else {
        RunMode::Interactive
    };
    let tty = if tty {
        if background {
            bail!("--tty is incompatible with --background");
        }
        // SAFETY: isatty on the inherited stdio fds; no memory safety concerns.
        if unsafe { libc::isatty(0) } != 1 || unsafe { libc::isatty(1) } != 1 {
            bail!("--tty requires stdin and stdout to be a terminal");
        }
        Some(Tty::local())
    } else {
        None
    };

    let (stream, sink) = connect(&addr).await?;
    let exec = CmdExec {
        name: cmd,
        args,
        clear_env,
        env,
        mode,
        dir,
        tty,
        user,
    };
    if exec.tty.is_some() {
        client_run_tty(stream, sink, exec).await
    } else {
        client_run_cmd(stream, sink, exec, stdin).await
    }
}

/// Turn the remote outcome into this process's own exit: reproduce the remote exit
/// code, or re-raise the remote's terminating signal so `vk` dies the same way the
/// command did. A result carrying neither (e.g. a backgrounded command) is success.
pub fn exit(result: CmdResult) -> ExitCode {
    if let Some(code) = result.code {
        std::process::exit(code);
    }
    if let Some(signal) = result.signal {
        reraise(signal);
        return ExitCode::from(128u8.wrapping_add(signal as u8));
    }
    ExitCode::SUCCESS
}

/// Re-raise `signal` despite vk's handlers (runs catch SIGTERM for shutdown), without
/// dumping core for a guest crash. Reject invalid or non-terminating signals from the
/// untrusted agent: a stop signal would suspend `vk`.
fn reraise(signal: i32) {
    let non_terminating = [
        libc::SIGCHLD,
        libc::SIGCONT,
        libc::SIGURG,
        libc::SIGWINCH,
        libc::SIGSTOP,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
    ];
    if !(1..=libc::SIGRTMAX()).contains(&signal) || non_terminating.contains(&signal) {
        return;
    }
    // SAFETY: plain syscalls on this process's own signal state and flags; a failure falls
    // through to the caller's 128+n.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::signal(signal, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(signal);
    }
}

#[cfg(test)]
mod tests {
    use super::{check_env, reraise, run};
    use vk_core::exec::client::Stdin;

    #[test]
    fn check_env_requires_key_equals_value() {
        // Well-formed pairs pass, including an empty value; no entries is fine.
        assert!(check_env(&[]).is_ok());
        assert!(check_env(&["KEY=value".into(), "EMPTY=".into()]).is_ok());

        // An entry without '=' is rejected, and the message names the offender.
        let err = check_env(&["OK=1".into(), "NOPE".into()]).unwrap_err();
        assert!(err.to_string().contains("NOPE"), "{err}");
    }

    #[test]
    fn reraise_dies_of_a_hooked_signal_without_core() {
        extern "C" fn swallow(_: libc::c_int) {}
        for signal in [libc::SIGTERM, libc::SIGABRT] {
            // SAFETY: the child runs only async-signal-safe calls before it dies or `_exit`s.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // Mimic a run's tokio handler and block the signal to test unblocking.
                unsafe {
                    libc::signal(signal, swallow as *const () as libc::sighandler_t);
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, signal);
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                }
                reraise(signal);
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            // SAFETY: reaping the child forked above.
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(
                libc::WIFSIGNALED(status),
                "signal {signal}: status {status:#x}"
            );
            assert_eq!(libc::WTERMSIG(status), signal);
            assert!(!libc::WCOREDUMP(status), "signal {signal} dumped core");
        }
    }

    #[test]
    fn reraise_returns_for_a_number_that_does_not_terminate() {
        // Filtered before any syscall, so these run in the test process itself: a stop
        // signal must not suspend it, nor 0 or an out-of-range number reach the kernel.
        for signal in [0, -1, libc::SIGSTOP, libc::SIGTSTP, libc::SIGCHLD, 1000] {
            reraise(signal);
        }
    }

    #[tokio::test]
    async fn tty_refuses_a_caller_that_keeps_its_stdin() {
        // TTY mode always consumes local stdin, so reject the incompatible pairing before
        // terminal validation. Non-terminal callers must receive this error too.
        let err = run(
            // The guard rejects the pairing before connecting.
            "/nonexistent/vk-tty-guard.socket".parse().unwrap(),
            false,
            false,
            vec![],
            None,
            true,
            None,
            "true".into(),
            vec![],
            Stdin::Closed,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--tty"), "{err}");
    }
}
