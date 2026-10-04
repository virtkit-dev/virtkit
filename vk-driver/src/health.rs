//! Compose service health: a unit's `healthcheck` test, run in its guest — through vk-agent in
//! a Linux guest, through qemu-ga in a Windows one.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use vk_core::addr::SocketAddr;

use crate::compose::{HealthCheck, HealthTest};

/// Where a service's test runs.
#[derive(Debug, Clone)]
pub enum Target {
    /// A Linux guest's vk-agent exec channel, and the user the test runs as: the service's, as
    /// Docker runs it as the container's.
    Agent {
        addr: SocketAddr,
        user: Option<String>,
    },
    /// A Windows guest's qemu-ga socket.
    GuestAgent(PathBuf),
}

/// How often a Windows test is asked whether it has exited.
const POLL: Duration = Duration::from_millis(100);

/// The most a Windows test waits for its guest agent to answer a connection, within its
/// timeout, and a kill after it waits for its own.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `test` once in the guest behind `target`, within `timeout`, and return its exit code.
/// A test that cannot run, or runs out of time, is an error saying why.
pub fn probe(target: &Target, test: &HealthTest, timeout: Duration) -> Result<i32> {
    match target {
        Target::Agent { addr, user } => probe_agent(addr, user.clone(), test, timeout),
        Target::GuestAgent(socket) => probe_guest_agent(socket, test, timeout),
    }
}

/// Update `failures`, the consecutive failure count, after a check fails `elapsed` into the
/// wait. Return `None` once the service is unhealthy; failures inside the start period do
/// not count.
pub fn count_failure(check: &HealthCheck, failures: u32, elapsed: Duration) -> Option<u32> {
    if elapsed < check.start_period {
        return Some(failures);
    }
    Some(failures + 1).filter(|&f| f < check.retries)
}

/// The argv a Linux guest runs `test` as: a shell-form test under `/bin/sh -c`.
fn linux_argv(test: &HealthTest) -> Vec<String> {
    match test {
        HealthTest::Exec(argv) => argv.clone(),
        HealthTest::Shell(line) => vec!["/bin/sh".into(), "-c".into(), line.clone()],
    }
}

fn probe_agent(
    addr: &SocketAddr,
    user: Option<String>,
    test: &HealthTest,
    timeout: Duration,
) -> Result<i32> {
    let argv = linux_argv(test);
    let addr = addr.clone();
    let run = crate::shutdown::on_own_runtime(move || async move {
        let quiet = crate::executor::OutputSink::Routed(std::sync::Arc::new(|_, _| {}));
        let exec = crate::executor::exec_script(&addr, &argv, Vec::new(), user, &quiet, None);
        let result = tokio::time::timeout(timeout, exec)
            .await
            .map_err(|_| anyhow!("timed out after {timeout:?}"))??;
        match (result.code, result.signal) {
            (Some(code), _) => Ok(code),
            (None, signal) => bail!("killed by signal {}", signal.unwrap_or(0)),
        }
    })
    .context("starting the healthcheck")?;
    run.join()
        .map_err(|_| anyhow!("the healthcheck panicked"))?
}

/// How a Windows guest runs a test.
#[derive(Debug, PartialEq, Eq)]
enum WindowsRun {
    /// A program and its arguments, started straight through qemu-ga's guest-exec.
    Program(String, Vec<String>),
    /// A command line, run from a batch file: qemu-ga quotes each argument its own way, which
    /// would hand `cmd /S /C` a quote in the line as `\"`.
    Line(String),
}

/// How a Windows guest runs `test`: a shell-form one under `cmd /S /C`, as Docker does.
fn windows_run(test: &HealthTest) -> Result<WindowsRun> {
    Ok(match test {
        HealthTest::Exec(argv) => {
            let (program, args) = argv.split_first().context("an empty test")?;
            WindowsRun::Program(program.clone(), args.to_vec())
        }
        HealthTest::Shell(line) => WindowsRun::Line(format!("cmd /S /C {line}")),
    })
}

/// Run `test` through the qemu-ga behind `socket`. Not through `vk exec`'s PowerShell wrapper,
/// whose start costs seconds: a test needs its exit code alone.
fn probe_guest_agent(socket: &Path, test: &HealthTest, timeout: Duration) -> Result<i32> {
    let run = windows_run(test)?;
    let deadline = Instant::now() + timeout;
    let left = || deadline.saturating_duration_since(Instant::now());
    let mut ga = crate::qga::Client::connect(socket, left().min(CONNECT_TIMEOUT))
        .context("the guest agent is unreachable")?;
    let (pid, bat) = match &run {
        WindowsRun::Program(program, args) => (ga.exec_within(program, args, left())?, None),
        WindowsRun::Line(line) => {
            let (pid, bat) = crate::winexec::start_line(&mut ga, line, left())?;
            (pid, Some(bat))
        }
    };
    let code = loop {
        match ga.exec_status_within(pid, left()) {
            Ok(status) if status.exited => break Ok(status.exitcode.unwrap_or(-1)),
            Ok(_) if !left().is_zero() => std::thread::sleep(POLL.min(left())),
            Ok(_) => break Err(anyhow!("still running")),
            Err(e) => break Err(e),
        }
    };
    code.or_else(|e| {
        kill(socket, pid, bat.as_deref());
        if left().is_zero() {
            bail!("timed out after {timeout:?}");
        }
        Err(e)
    })
}

/// Kill the Windows test `pid` and what it started, and delete its batch file `bat`: best
/// effort, on a connection of its own, as the test's may still await a late answer.
fn kill(socket: &Path, pid: i64, bat: Option<&str>) {
    let _ = crate::qga::Client::connect(socket, CONNECT_TIMEOUT)
        .and_then(|mut ga| ga.exec_within("cmd.exe", &kill_args(pid, bat), CONNECT_TIMEOUT));
}

/// The cmd.exe arguments that kill `pid`'s tree, then delete `bat`. Each goes as an argument of
/// its own that needs no quoting, so cmd.exe reads them as written.
fn kill_args(pid: i64, bat: Option<&str>) -> Vec<String> {
    let pid = pid.to_string();
    let mut args = vec!["/d", "/c", "taskkill", "/PID", &pid, "/T", "/F"];
    if let Some(bat) = bat {
        args.extend(["&", "del", "/q", bat]);
    }
    args.into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(retries: u32, start_period: Duration) -> HealthCheck {
        HealthCheck {
            test: HealthTest::Shell("true".into()),
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            retries,
            start_period,
        }
    }

    #[test]
    fn failures_count_after_the_start_period_until_the_retries_run_out() {
        let twice = check(2, Duration::from_secs(10));
        assert_eq!(count_failure(&twice, 0, Duration::from_secs(9)), Some(0));
        assert_eq!(count_failure(&twice, 0, Duration::from_secs(10)), Some(1));
        assert_eq!(count_failure(&twice, 1, Duration::from_secs(11)), None);
        let once = check(1, Duration::ZERO);
        assert_eq!(count_failure(&once, 0, Duration::ZERO), None);
    }

    #[test]
    fn a_linux_shell_form_test_runs_under_sh() {
        let exec = HealthTest::Exec(vec!["pg_isready".into(), "-q".into()]);
        assert_eq!(linux_argv(&exec), ["pg_isready", "-q"]);
        let shell = HealthTest::Shell("nc -z db 5432 || exit 1".into());
        assert_eq!(
            linux_argv(&shell),
            ["/bin/sh", "-c", "nc -z db 5432 || exit 1"]
        );
    }

    #[test]
    fn a_windows_shell_form_test_keeps_its_quotes_and_operators_for_cmd() {
        let exec = HealthTest::Exec(vec!["nltest".into(), "/dsgetdc:corp.lab".into()]);
        assert_eq!(
            windows_run(&exec).unwrap(),
            WindowsRun::Program("nltest".into(), vec!["/dsgetdc:corp.lab".into()])
        );
        assert!(windows_run(&HealthTest::Exec(Vec::new())).is_err());
        let shell = HealthTest::Shell(r#"findstr "a b" C:\x.txt & exit 0"#.into());
        let WindowsRun::Line(line) = windows_run(&shell).unwrap() else {
            panic!("a shell-form test runs from a command line");
        };
        assert_eq!(line, r#"cmd /S /C findstr "a b" C:\x.txt & exit 0"#);
        // The batch file runs it verbatim: its `&` is escaped for the batch file alone.
        let bat = crate::winexec::script(&line, &[], None, None);
        assert!(
            bat.contains(r#"cmd /S /C findstr "a b" C:\x.txt ^& exit 0"#),
            "{bat}"
        );
    }

    #[test]
    fn a_kill_takes_the_tests_tree_and_its_batch_file() {
        assert_eq!(
            kill_args(42, None),
            ["/d", "/c", "taskkill", "/PID", "42", "/T", "/F"]
        );
        assert_eq!(
            kill_args(42, Some(r"C:\run\x.cmd")),
            [
                "/d",
                "/c",
                "taskkill",
                "/PID",
                "42",
                "/T",
                "/F",
                "&",
                "del",
                "/q",
                r"C:\run\x.cmd"
            ]
        );
    }

    #[test]
    fn a_test_whose_guest_does_not_answer_fails_within_its_timeout() {
        // A socket nobody listens on, under a name no other run computes.
        let nonce = crate::scratch::random_nonce().unwrap();
        let socket = std::env::temp_dir().join(format!("vk-health-{nonce}.sock"));
        let started = Instant::now();
        let err = probe(
            &Target::GuestAgent(socket),
            &HealthTest::Shell("exit 0".into()),
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("unreachable"), "{err:#}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
