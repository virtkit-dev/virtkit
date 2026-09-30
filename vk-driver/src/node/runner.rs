//! The gitlab-runner a node supervises in `[node] runner = "managed"` mode: started as a child
//! of `vk node run`, restarted when it dies, and stopped — `SIGQUIT`, which makes it stop
//! requesting jobs and exit once the ones it has are finished — whenever acquisition is to
//! stop. It is not started again until acquisition resumes. Stopping acquisition is thereby a
//! state of the node, not a `concurrent` of zero, which gitlab-runner does not have; nor has
//! it a way back from `SIGQUIT`, so a resume that comes while the runner is still quitting
//! waits for it to exit and then starts a new one.
//!
//! The runner outlives a `vk node` killed outright — a parent-death signal would follow the
//! thread that forked, not the process, and a runner killed with its node would abort its
//! jobs. So the runner's pid and start time are kept in `<state_dir>/node/runner.pid`, and a
//! `vk node` that finds that process still there adopts it rather than start a second: it
//! counts it as running, quits it when acquisition is to stop, and waits for it to exit
//! before starting its own. Only the moment between spawning a runner and recording it is
//! uncovered.
//!
//! The child starts with every signal at its default disposition and none blocked, whatever
//! `vk node run` inherited: a runner that ignores `SIGQUIT` because the shell that started the
//! node did could never be stopped.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use vk_fleet_proto::RunnerState;

/// The first restart delay, and the ceiling doubling reaches: a runner that cannot start —
/// a broken config, say — is retried without being hammered.
const RESTART: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// A runner that stayed up this long was working, so its next death restarts the backoff.
const STABLE_RUN: Duration = Duration::from_secs(60);

/// How often an adopted runner, which is not our child to wait for, is checked for.
const ADOPTED_POLL: Duration = Duration::from_millis(500);

const PID_FILE: &str = "runner.pid";

/// What to run, and the node directory its record is kept in.
#[derive(Clone, Debug)]
pub struct Spec {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub dir: PathBuf,
}

/// What the supervisor follows.
pub struct Signals {
    /// Whether the runner may take jobs.
    pub allowed: watch::Receiver<bool>,
    /// The node is stopping: quit the runner, wait for it, and return.
    pub halt: watch::Receiver<bool>,
    /// Stop waiting: `SIGTERM` to the runner — which abandons its jobs — and return.
    pub abort: watch::Receiver<bool>,
}

/// Supervise the runner until `halt` — or `abort` — says to stop, reporting its process on
/// `state`. It reads `Running` from before the spawn until the process has been waited for, so
/// nothing that reads it — a drain above all — ever sees a runner that exists as stopped.
pub async fn supervise(spec: Spec, mut sig: Signals, state: watch::Sender<RunnerState>) {
    let mut backoff = RESTART.0;
    loop {
        if let Some(orphan) = recorded(&spec) {
            adopt(orphan, &mut sig, &state).await;
            forget(&spec);
        }
        // `send_replace`: the state is kept whether or not anyone is watching.
        state.send_replace(RunnerState::Stopped);
        if *sig.halt.borrow() || *sig.abort.borrow() {
            return;
        }
        if !*sig.allowed.borrow_and_update() {
            tokio::select! {
                _ = sig.allowed.changed() => {}
                _ = sig.halt.wait_for(|&h| h) => return,
                _ = sig.abort.wait_for(|&a| a) => return,
            }
            continue;
        }
        state.send_replace(RunnerState::Running);
        let mut child = match command(&spec).spawn() {
            Ok(child) => child,
            Err(e) => {
                state.send_replace(RunnerState::Stopped);
                eprintln!(
                    "vk node: starting {}: {e}; retrying in {}s",
                    spec.binary.display(),
                    backoff.as_secs()
                );
                if wait_or_stop(backoff, &mut sig).await {
                    return;
                }
                backoff = (backoff * 2).min(RESTART.1);
                continue;
            }
        };
        let started = Instant::now();
        let pid = child.id().and_then(|p| i32::try_from(p).ok());
        if let Some(pid) = pid {
            record(&spec, pid);
        }
        eprintln!("vk node: gitlab-runner started (pid {})", pid.unwrap_or(0));
        let quit = tokio::select! {
            status = child.wait() => {
                eprintln!("vk node: gitlab-runner exited ({})", describe(status));
                false
            }
            _ = sig.allowed.wait_for(|&a| !a) => true,
            _ = sig.halt.wait_for(|&h| h) => true,
            _ = sig.abort.wait_for(|&a| a) => true,
        };
        if quit {
            let signal = if *sig.abort.borrow() {
                libc::SIGTERM
            } else {
                libc::SIGQUIT
            };
            if let Some(pid) = pid {
                send(pid, signal);
            }
            state.send_replace(RunnerState::Quitting);
            let exited = tokio::select! {
                status = child.wait() => Some(status),
                _ = sig.abort.wait_for(|&a| a), if signal != libc::SIGTERM => None,
            };
            let status = match exited {
                Some(status) => status,
                None => {
                    if let Some(pid) = pid {
                        send(pid, libc::SIGTERM);
                    }
                    // Waited for all the same, so the runner is reaped before returning.
                    child.wait().await
                }
            };
            eprintln!("vk node: gitlab-runner exited ({})", describe(status));
            forget(&spec);
            backoff = RESTART.0;
            continue;
        }
        forget(&spec);
        state.send_replace(RunnerState::Stopped);
        if started.elapsed() >= STABLE_RUN {
            backoff = RESTART.0;
        }
        if wait_or_stop(backoff, &mut sig).await {
            return;
        }
        backoff = (backoff * 2).min(RESTART.1);
    }
}

/// `gitlab-runner run --config <config>`, in a process group of its own — so a Ctrl-C at
/// `vk node run`'s terminal reaches the node, which quits the runner gracefully, rather than
/// killing the runner outright — with its signals reset (see the module doc).
fn command(spec: &Spec) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&spec.binary);
    cmd.arg("run")
        .arg("--config")
        .arg(&spec.config)
        .stdin(std::process::Stdio::null())
        .process_group(0);
    // Read before the fork: the child calls nothing but the two below.
    let last = libc::SIGRTMAX();
    // SAFETY: the closure runs in the child between fork and exec, and calls only sigaction,
    // sigemptyset and sigprocmask on values built on its stack — all async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            for signal in 1..=last {
                if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                    // Signals the kernel reserves fail with EINVAL; nothing to reset there.
                    libc::sigaction(signal, &default, std::ptr::null_mut());
                }
            }
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            if libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

/// Signal a runner. Nothing to do on failure: the only one is a process already gone, which
/// the wait that follows sees for itself.
fn send(pid: i32, signal: libc::c_int) {
    let name = if signal == libc::SIGQUIT {
        "SIGQUIT (take no new jobs, finish the running ones)"
    } else {
        "SIGTERM (abandon the running jobs)"
    };
    eprintln!("vk node: {name} to gitlab-runner (pid {pid})");
    // SAFETY: a plain kill of a pid checked to be the runner — our unreaped child, or an
    // adopted one whose start time still matches.
    unsafe { libc::kill(pid, signal) };
}

/// A runner left by an earlier `vk node`: follow it until it exits, quitting it when
/// acquisition is to stop and terminating it on `abort`. It is not our child, so it is
/// polled for rather than waited on.
async fn adopt(orphan: Orphan, sig: &mut Signals, state: &watch::Sender<RunnerState>) {
    eprintln!(
        "vk node: gitlab-runner pid {} from an earlier vk node is still running; following it \
         rather than starting another",
        orphan.pid
    );
    state.send_replace(RunnerState::Running);
    let mut quit_sent = false;
    let mut term_sent = false;
    while orphan.alive() {
        if !term_sent && *sig.abort.borrow() {
            send(orphan.pid, libc::SIGTERM);
            term_sent = true;
        } else if !quit_sent && (!*sig.allowed.borrow() || *sig.halt.borrow()) {
            send(orphan.pid, libc::SIGQUIT);
            quit_sent = true;
            state.send_replace(RunnerState::Quitting);
        }
        tokio::select! {
            () = tokio::time::sleep(ADOPTED_POLL) => {}
            _ = sig.allowed.changed() => {}
            _ = sig.halt.changed() => {}
            _ = sig.abort.changed() => {}
        }
    }
    eprintln!(
        "vk node: the adopted gitlab-runner (pid {}) has exited",
        orphan.pid
    );
}

/// A runner process named by the record, as it was when it was recorded.
struct Orphan {
    pid: i32,
    start: u64,
}

impl Orphan {
    /// Still the same process: there, not a zombie, and started when it was recorded — a pid
    /// reused by another process has another start time.
    fn alive(&self) -> bool {
        stat(self.pid)
            .is_some_and(|(state, start)| start == self.start && !matches!(state, 'Z' | 'X'))
    }
}

/// The recorded runner, if that process is still there.
fn recorded(spec: &Spec) -> Option<Orphan> {
    let text = std::fs::read_to_string(pid_file(&spec.dir)).ok()?;
    let (pid, start) = text.trim().split_once(' ')?;
    let orphan = Orphan {
        pid: pid.parse().ok()?,
        start: start.parse().ok()?,
    };
    orphan.alive().then_some(orphan)
}

fn record(spec: &Spec, pid: i32) {
    let Some((_, start)) = stat(pid) else {
        return;
    };
    let path = pid_file(&spec.dir);
    if let Err(e) = vk_fs::write_atomic(&path, format!("{pid} {start}\n").as_bytes(), 0o600) {
        // The runner runs regardless; only a later `vk node` finding it is lost.
        eprintln!("vk node: recording the runner in {}: {e:#}", path.display());
    }
}

fn forget(spec: &Spec) {
    // Absent is the goal; any other failure leaves a record naming a process that is gone,
    // which the start-time check reads as no runner.
    let _ = std::fs::remove_file(pid_file(&spec.dir));
}

fn pid_file(dir: &Path) -> PathBuf {
    dir.join(PID_FILE)
}

/// A process's state letter and start time, in clock ticks since boot: fields 3 and 22 of
/// `/proc/<pid>/stat`, counted after the command name, which may itself hold spaces and
/// parentheses.
fn stat(pid: i32) -> Option<(char, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = after.split_whitespace();
    let state = fields.next()?.chars().next()?;
    Some((state, fields.nth(18)?.parse().ok()?))
}

/// Sleep `d` before a restart; true when the node is stopping. A change of `allowed` ends the
/// wait early, since the loop re-reads it anyway.
async fn wait_or_stop(d: Duration, sig: &mut Signals) -> bool {
    tokio::select! {
        () = tokio::time::sleep(d) => false,
        _ = sig.allowed.changed() => false,
        _ = sig.halt.wait_for(|&h| h) => true,
        _ = sig.abort.wait_for(|&a| a) => true,
    }
}

fn describe(status: std::io::Result<std::process::ExitStatus>) -> String {
    match status {
        Ok(s) => s.to_string(),
        Err(e) => format!("unknown status: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gitlab-runner stand-in: logs its pid and arguments, runs until killed, and on SIGQUIT
    /// takes a moment to finish before it exits, as a runner finishing its jobs does.
    fn stub(tag: &str) -> (Spec, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-node-runner-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("starts");
        let script = dir.join("gitlab-runner");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$$ $@\" >> {log}\ntrap 'sleep 0.3; exit 0' QUIT\n\
                 while true; do sleep 0.05; done\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let spec = Spec {
            binary: script,
            config: "/cfg.toml".into(),
            dir,
        };
        (spec, log)
    }

    struct Harness {
        allow: watch::Sender<bool>,
        halt: watch::Sender<bool>,
        abort: watch::Sender<bool>,
        state: watch::Receiver<RunnerState>,
        task: tokio::task::JoinHandle<()>,
    }

    fn start(spec: &Spec, allowed: bool) -> Harness {
        let (allow, allowed) = watch::channel(allowed);
        let (halt, halted) = watch::channel(false);
        let (abort, aborted) = watch::channel(false);
        let (state_tx, state) = watch::channel(RunnerState::Stopped);
        let sig = Signals {
            allowed,
            halt: halted,
            abort: aborted,
        };
        let task = tokio::spawn(supervise(spec.clone(), sig, state_tx));
        Harness {
            allow,
            halt,
            abort,
            state,
            task,
        }
    }

    async fn until(rx: &mut watch::Receiver<RunnerState>, want: RunnerState) {
        tokio::time::timeout(Duration::from_secs(10), rx.wait_for(|&v| v == want))
            .await
            .expect("the runner never reached the expected state")
            .unwrap();
    }

    fn starts(log: &Path) -> Vec<(i32, String)> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| {
                let (pid, args) = l.split_once(' ').unwrap();
                (pid.parse().unwrap(), args.to_string())
            })
            .collect()
    }

    async fn started(log: &Path, n: usize) {
        for _ in 0..200 {
            if starts(log).len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the runner was not started {n} time(s)");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_runner_is_restarted_quit_on_stop_and_started_again_on_resume() {
        let (spec, log) = stub("supervise");
        let mut h = start(&spec, true);
        until(&mut h.state, RunnerState::Running).await;
        started(&log, 1).await;
        let (pid, args) = starts(&log)[0].clone();
        assert_eq!(args, "run --config /cfg.toml");

        // Dies on its own while allowed: started again.
        // SAFETY: a plain kill of the stub's own pid.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        until(&mut h.state, RunnerState::Stopped).await;
        started(&log, 2).await;
        until(&mut h.state, RunnerState::Running).await;

        // Acquisition stops: quitting until it has exited, then stopped, and not started again.
        h.allow.send(false).unwrap();
        until(&mut h.state, RunnerState::Quitting).await;
        until(&mut h.state, RunnerState::Stopped).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(starts(&log).len(), 2);

        // Resumed: started again.
        h.allow.send(true).unwrap();
        started(&log, 3).await;
        until(&mut h.state, RunnerState::Running).await;

        // The node stops: the runner is quit and the supervisor returns once it has gone.
        h.halt.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), h.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*h.state.borrow(), RunnerState::Stopped);
        assert!(recorded(&spec).is_none());
        let _ = std::fs::remove_dir_all(&spec.dir);
    }

    /// A shell that ignores SIGQUIT and starts the node must not hand that to the runner.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_runner_hears_sigquit_even_if_the_node_ignores_it() {
        let (spec, log) = stub("sigign");
        // SAFETY: ignoring SIGQUIT in this test process, which does not rely on it.
        unsafe { libc::signal(libc::SIGQUIT, libc::SIG_IGN) };
        let mut h = start(&spec, true);
        started(&log, 1).await;
        h.allow.send(false).unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            h.state.wait_for(|&s| s == RunnerState::Stopped),
        )
        .await
        .expect("the runner ignored SIGQUIT")
        .unwrap();
        h.halt.send(true).unwrap();
        h.task.await.unwrap();
        let _ = std::fs::remove_dir_all(&spec.dir);
    }

    /// A node killed outright leaves its runner running; the next one follows that runner
    /// rather than start a second, and quits it when acquisition is to stop.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_runner_left_by_a_killed_node_is_adopted_not_doubled() {
        let (spec, log) = stub("adopt");
        let mut first = start(&spec, true);
        started(&log, 1).await;
        until(&mut first.state, RunnerState::Running).await;
        // The node dies: its supervisor is gone, its runner is not.
        first.task.abort();
        let _ = first.task.await;
        let (pid, _) = starts(&log)[0].clone();
        // SAFETY: probing the stub's pid.
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0);

        // Ready: the new node follows it.
        let mut ready = start(&spec, true);
        until(&mut ready.state, RunnerState::Running).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(starts(&log).len(), 1, "a second runner was started");
        ready.task.abort();
        let _ = ready.task.await;

        // Drained: the node after that quits it at once and starts nothing.
        let mut drained = start(&spec, false);
        until(&mut drained.state, RunnerState::Quitting).await;
        until(&mut drained.state, RunnerState::Stopped).await;
        assert_eq!(starts(&log).len(), 1);
        assert!(recorded(&spec).is_none());
        drained.abort.send(true).unwrap();
        drained.task.await.unwrap();
        let _ = std::fs::remove_dir_all(&spec.dir);
    }

    /// A second signal to the node stops waiting for the jobs: SIGTERM to the runner.
    #[tokio::test(flavor = "multi_thread")]
    async fn abort_terminates_a_quitting_runner() {
        use std::os::unix::fs::PermissionsExt;
        let (spec, log) = stub("abort");
        // A runner that ignores SIGQUIT's request to hurry: it never finishes on its own.
        std::fs::write(
            &spec.binary,
            format!(
                "#!/bin/sh\necho \"$$ $@\" >> {}\ntrap '' QUIT\nwhile true; do sleep 0.05; done\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&spec.binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut h = start(&spec, true);
        started(&log, 1).await;
        h.halt.send(true).unwrap();
        until(&mut h.state, RunnerState::Quitting).await;
        h.abort.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), h.task)
            .await
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_dir_all(&spec.dir);
    }

    #[test]
    fn the_start_time_is_read_past_the_command_name() {
        let own = i32::try_from(std::process::id()).unwrap();
        let (state, start) = stat(own).unwrap();
        // Running, or asleep — interruptibly or not, as a loaded host may catch it.
        assert!(matches!(state, 'R' | 'S' | 'D'), "{state}");
        assert!(start > 0);
        assert_eq!(stat(i32::MAX), None);
    }
}
