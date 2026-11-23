//! [`Kept`] and [`Lifeline`] kill a fixture's process group on drop, including during panic
//! unwinding. If the test process dies first, even by `SIGKILL`, a watchdog sees EOF on its
//! pipe and kills the group, including any grandchildren still in it.
//!
//! The watchdog leads a separate group so it survives a runner timeout that kills the test's
//! group. It runs alongside the fixtures to preserve their process trees, memory readings
//! and command lines.

use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

/// Owns a watchdog-led process group for commands added with [`Lifeline::join`].
pub(crate) struct Lifeline {
    watchdog: Child,
    /// The pipe's only write end. CLOEXEC, so no exec'd child keeps the watchdog waiting.
    _alive: std::io::PipeWriter,
}

impl Lifeline {
    pub(crate) fn new() -> Self {
        let (read, alive) = std::io::pipe().expect("a pipe for a test child's watchdog");
        // `kill 0` is the shell's own group: the children joined to it, and itself.
        let watchdog = Command::new("sh")
            .args(["-c", "read _; kill -s KILL 0"])
            .stdin(read)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawning a test child's watchdog");
        Self {
            watchdog,
            _alive: alive,
        }
    }

    /// Start `cmd` in the watchdog's group. Calling `setsid` or changing groups escapes cleanup.
    pub(crate) fn join<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.process_group(self.pgid())
    }

    fn pgid(&self) -> i32 {
        i32::try_from(self.watchdog.id()).unwrap()
    }

    /// SIGKILL the whole group now. The watchdog is reaped only on drop, so until then its
    /// pid names this group and no other.
    pub(crate) fn kill(&self) {
        // SAFETY: kill only delivers a signal.
        unsafe { libc::kill(-self.pgid(), libc::SIGKILL) };
    }
}

impl Drop for Lifeline {
    fn drop(&mut self) {
        self.kill();
        let _ = self.watchdog.wait();
    }
}

/// Kills the child's [`Lifeline`] group and reaps the child on drop.
pub(crate) struct Kept {
    child: Child,
    line: Lifeline,
}

impl Kept {
    pub(crate) fn spawn(cmd: &mut Command) -> Self {
        let line = Lifeline::new();
        let child = line.join(cmd).spawn().expect("spawning a test child");
        Self { child, line }
    }
}

impl std::ops::Deref for Kept {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for Kept {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        self.line.kill();
        let _ = self.child.wait();
    }
}

/// [`inherit_lifeline`] sets this to the descriptor [`GROUP_WATCHDOG_SH`] reads.
const LIFELINE_FD: &str = "VK_TEST_LIFELINE_FD";

/// The test process keeps the writer until exit. Both ends are CLOEXEC by default.
fn process_lifeline() -> &'static (std::io::PipeReader, std::io::PipeWriter) {
    static LIFELINE: std::sync::OnceLock<(std::io::PipeReader, std::io::PipeWriter)> =
        std::sync::OnceLock::new();
    LIFELINE.get_or_init(|| std::io::pipe().expect("a pipe for this test process's lifeline"))
}

/// Pass the open lifeline reader to [`GROUP_WATCHDOG_SH`] when the code under test sets
/// the command's process group.
pub(crate) fn inherit_lifeline(cmd: &mut Command) -> &mut Command {
    use std::os::fd::AsRawFd;
    let fd = process_lifeline().0.as_raw_fd();
    // SAFETY: fcntl is async-signal-safe. The static keeps fd open, and clearing CLOEXEC
    // in the child preserves the descriptor number passed in the environment.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.env(LIFELINE_FD, fd.to_string())
}

/// Start a background watchdog in a script that leads its own process group. On test process
/// exit it kills that group, even if the script has already exited. Using the test's group
/// would kill the test run.
///
/// [`inherit_lifeline`] passes an open reader, so a late read sees EOF even if the writer
/// has already exited. A missing descriptor variable aborts the script. Redirecting the
/// watchdog's output lets readers see EOF when the script exits.
pub(crate) const GROUP_WATCHDOG_SH: &str = ": \"${VK_TEST_LIFELINE_FD:?not run through \
     inherit_lifeline}\"\n{ read _ <&\"$VK_TEST_LIFELINE_FD\"; kill -s KILL 0; } \
     >/dev/null 2>&1 &\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// A pidfd for `pid`, taken while it is known to be running, so it keeps naming that
    /// process even once its pid is reused.
    fn pidfd(pid: i32) -> OwnedFd {
        // SAFETY: pidfd_open of a pid, into a fresh descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: a fresh descriptor owned by nothing else.
        unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) }
    }

    /// Whether `fd` turns readable (or, for a pidfd, its process exits) within `ms`. The
    /// bound only turns a regression into a failure rather than a hang.
    fn ready_within(fd: &impl AsRawFd, ms: i32) -> bool {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: poll reads and writes the one local pollfd.
            match unsafe { libc::poll(&mut poll, 1, ms) } {
                n if n >= 0 => return n == 1,
                _ => {
                    let e = std::io::Error::last_os_error();
                    assert_eq!(e.kind(), std::io::ErrorKind::Interrupted, "{e}");
                }
            }
        }
    }

    /// Read the first `tag pid` report with a one-minute timeout. The harness can write
    /// earlier lines or prefix the tag.
    fn reported(from: std::io::PipeReader, tag: &str) -> i32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut from = from;
        let mut got = Vec::new();
        loop {
            if let Some(line) = got.split(|&b| b == b'\n').find_map(|line: &[u8]| {
                let line = String::from_utf8_lossy(line);
                let (_, pid) = line.split_once(&format!("{tag} "))?;
                pid.trim().parse().ok()
            }) {
                return line;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let ms = i32::try_from(left.as_millis()).unwrap();
            assert!(ready_within(&from, ms), "no {tag} reported: {got:?}");
            let mut buf = [0u8; 512];
            let n = std::io::Read::read(&mut from, &mut buf).unwrap();
            assert_ne!(n, 0, "the reporter exited without a {tag}: {got:?}");
            got.extend_from_slice(&buf[..n]);
        }
    }

    /// Write directly to stdout to bypass the harness's `println!` capture.
    fn report(tag: &str, pid: u32) {
        let mut out = std::io::stdout();
        std::io::Write::write_all(&mut out, format!("{tag} {pid}\n").as_bytes()).unwrap();
        std::io::Write::flush(&mut out).unwrap();
    }

    /// Return the guarded shell and its background `sleep`'s pid.
    fn kept_with_a_grandchild() -> (Kept, i32) {
        let (read, write) = std::io::pipe().unwrap();
        let kept = Kept::spawn(
            Command::new("sh")
                .args(["-c", "sleep 100000 & echo grandchild $!; wait"])
                .stdout(write),
        );
        (kept, reported(read, "grandchild"))
    }

    #[test]
    fn dropping_kills_the_whole_group() {
        let (kept, pid) = kept_with_a_grandchild();
        let grandchild = pidfd(pid);
        assert!(!ready_within(&grandchild, 0));
        drop(kept);
        assert!(ready_within(&grandchild, 30_000), "outlived its drop");
    }

    const STAND_IN: &str = "VK_TEST_LIFELINE_STAND_IN";
    const STAND_IN_TEST: &str = "testchild::tests::stand_in_test_process";

    /// Run [`stand_in_test_process`] in `mode` and return it with its background `sleep`'s
    /// pid. The guard cleans up on failure. Its piped stdin gates the late-watchdog test.
    fn stand_in(mode: &str) -> (Kept, i32) {
        let (read, write) = std::io::pipe().unwrap();
        let mut cmd = crate::dev::testutil::child_test(STAND_IN_TEST);
        cmd.env(STAND_IN, mode)
            .stdin(Stdio::piped())
            .stdout(write)
            .stderr(Stdio::null());
        let kept = Kept::spawn(&mut cmd);
        drop(cmd);
        (kept, reported(read, "grandchild"))
    }

    /// Reap the stand-in after SIGKILL bypasses its destructors.
    fn kill(stand_in: &mut Kept) {
        stand_in.kill().unwrap();
        stand_in.wait().unwrap();
    }

    #[test]
    fn a_killed_test_process_leaves_nothing_running() {
        let (mut stand_in, pid) = stand_in("kept");
        let grandchild = pidfd(pid);
        kill(&mut stand_in);
        assert!(ready_within(&grandchild, 30_000), "survived its test");
    }

    /// Hold the watchdog behind the stand-in's stdin until SIGKILL closes the lifeline
    /// writer. Its inherited reader must still see EOF.
    #[test]
    fn a_watchdog_late_to_its_read_still_ends_the_group() {
        let (mut stand_in, pid) = stand_in("inherited");
        let grandchild = pidfd(pid);
        let gate = stand_in.stdin.take().unwrap();
        kill(&mut stand_in);
        assert!(
            !ready_within(&grandchild, 0),
            "ended before its watchdog was let go"
        );
        drop(gate);
        assert!(ready_within(&grandchild, 30_000), "survived its test");
    }

    /// Runs only when marked by [`child_test`]. Both modes report the background `sleep`'s
    /// pid and wait for SIGKILL. `kept` guards the shell with [`Kept`]. In `inherited` the
    /// shell leads its own group and starts [`GROUP_WATCHDOG_SH`] when stdin closes.
    ///
    /// [`child_test`]: crate::dev::testutil::child_test
    #[test]
    fn stand_in_test_process() {
        let Some(mode) = crate::dev::testutil::child_marker(STAND_IN) else {
            return;
        };
        // Held, never dropped: this process is killed before it could reap either.
        let (mut _kept, mut _script) = (None, None);
        let pid = match mode.to_str() {
            Some("kept") => {
                let (kept, pid) = kept_with_a_grandchild();
                _kept = Some(kept);
                pid
            }
            Some("inherited") => {
                let (read, write) = std::io::pipe().unwrap();
                // Not kept: only the watchdog may end it. Its own `read` holds it back.
                let script = format!(
                    "exec 3<&0\n{{ read _ <&3\n{GROUP_WATCHDOG_SH}}} &\n\
                     sleep 100000 & echo grandchild $!; wait"
                );
                _script = Some(
                    inherit_lifeline(
                        Command::new("sh")
                            .args(["-c", &script])
                            .stdout(write)
                            .process_group(0),
                    )
                    .spawn()
                    .unwrap(),
                );
                reported(read, "grandchild")
            }
            other => panic!("{STAND_IN}={other:?}"),
        };
        report("grandchild", u32::try_from(pid).unwrap());
        loop {
            std::thread::park();
        }
    }
}
