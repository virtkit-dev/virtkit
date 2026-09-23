//! Output that cannot panic its process. `println!` and `eprintln!` panic when a write fails,
//! and the job supervisor, the switch and the forwards write their stdout and stderr to log
//! files (a CI job's in its job dir): on a full filesystem every line they print would kill
//! them, and a job with them.
//!
//! [`relay`] points stdout and stderr at a pipe instead, whose writes do not fail while this
//! process drains it. A thread appends what comes through to where the stream went before and
//! drops whatever that refuses. One guard for the whole process, rather than a non-panicking
//! print at each call site: the supervisor prints through the image, build, registry and switch
//! code it calls, and a call site missed would still panic.
//!
//! A child spawned with inherited stdio gets the pipe too: its output is relayed while this
//! process lives, and once this process is gone its writes end it by `SIGPIPE` (which `Command`
//! puts back to its default in every child), or fail with `EPIPE` where it ignores that
//! signal. A process killed
//! outright loses what it wrote in the moment before, still in the pipe.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long a drain waits for more output before it looks at whether it has been told to stop.
const IDLE_MS: libc::c_int = 100;
/// The longest a drain keeps copying once told to stop: a child that inherited the stream and
/// keeps writing must not hold this process's exit up.
const STOP_WITHIN: Duration = Duration::from_millis(500);

/// The relay this process runs, if any. Process-wide because the streams are: [`finish`] has to
/// reach it from an exit path far from whoever set it up.
static ACTIVE: Mutex<Option<Relay>> = Mutex::new(None);

/// Holds the relay [`relay`] started; dropping it is [`finish`]. The guard of a call that found
/// a relay already running owns nothing, and ends nothing.
#[must_use = "the relay ends when the guard drops"]
pub struct Guard {
    owner: bool,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.owner {
            finish();
        }
    }
}

/// Relay stdout and stderr until the returned guard drops. Where the pipes cannot be set up
/// the streams stay as they were: output that can panic is no worse than before.
pub fn relay() -> Guard {
    let mut active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
    // A second relay would save the first one's pipe as the stream to put back, and be left
    // writing into it once the first is gone.
    if active.is_some() {
        return Guard { owner: false };
    }
    *active = Relay::start();
    Guard {
        owner: active.is_some(),
    }
}

/// Put stdout and stderr back and wait for what was already written to reach them. For a path
/// that leaves with `std::process::exit`, which runs no destructors; a no-op once done. Output
/// printed after it goes to the streams directly again, and can panic as it did before.
pub fn finish() {
    let relay = ACTIVE.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(relay);
}

/// stdout and stderr relayed while this lives. Dropping it puts both streams back and waits for
/// what was already written to reach them, so a process's last line — the error it exits on, a
/// panic message unwinding past the guard — is not lost.
struct Relay {
    streams: Vec<Stream>,
    stop: Arc<AtomicBool>,
}

struct Stream {
    /// The descriptors relayed through this stream's pipe: 1, 2, or both.
    fds: Vec<RawFd>,
    /// What they were before, put back on drop.
    saved: OwnedFd,
    drain: Option<JoinHandle<()>>,
}

impl Relay {
    fn start() -> Option<Relay> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut relay = Relay {
            streams: Vec::new(),
            stop: Arc::clone(&stop),
        };
        let (out, err) = (libc::STDOUT_FILENO, libc::STDERR_FILENO);
        // One pipe for both where they are the same file, as the supervisor's log is: two
        // drains would each append in their own time and reorder the lines between them.
        // A closed stream is left closed: there is nothing to relay it to, and a descriptor
        // taken for it would be one this process hands out as its own later.
        let groups = match (file_id(out), file_id(err)) {
            (Some(a), Some(b)) if a == b => vec![vec![out, err]],
            (a, b) => [(out, a), (err, b)]
                .into_iter()
                .filter(|(_, id)| id.is_some())
                .map(|(fd, _)| vec![fd])
                .collect(),
        };
        for fds in groups {
            // Pushed one at a time, so a failure part-way leaves the streams already relayed
            // to be put back by the drop of `relay` on the way out.
            relay
                .streams
                .push(Stream::start(fds, Arc::clone(&stop)).ok()?);
        }
        Some(relay)
    }
}

/// The `(device, inode)` of the file behind `fd`.
fn file_id(fd: RawFd) -> Option<(u64, u64)> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat fills the whole struct through the pointer, and only on success.
    let st = unsafe {
        if libc::fstat(fd, st.as_mut_ptr()) != 0 {
            return None;
        }
        st.assume_init()
    };
    Some((st.st_dev, st.st_ino))
}

impl Stream {
    fn start(fds: Vec<RawFd>, stop: Arc<AtomicBool>) -> std::io::Result<Stream> {
        let first = *fds.first().ok_or(std::io::ErrorKind::InvalidInput)?;
        // Close-on-exec: the saved copy is this process's alone, and a child holding it
        // would keep writing past the relay.
        let saved = dup_above_std(first)?;
        let mut ends = [0; 2];
        // SAFETY: pipe2 writes two descriptors into the array we own, and only on success.
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both ends were just returned to us and nothing else owns them.
        let (read, write) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        // With a standard stream closed, pipe2 can hand out its number; the dup2 below or a
        // later open would then take an end from under its owner.
        let (read, write) = (above_std(read)?, above_std(write)?);
        let dest = File::from(saved.try_clone()?);
        let drain = std::thread::Builder::new()
            .name("vk-outrelay".into())
            .spawn(move || drain(File::from(read), dest, &stop))?;
        // Last, once the drain is running: from here on a write to these descriptors goes to
        // the pipe. The copies dup2 makes are inherited across exec, as the originals were.
        for (i, &fd) in fds.iter().enumerate() {
            // SAFETY: both descriptors are open; dup2 replaces `fd` atomically.
            if unsafe { libc::dup2(write.as_raw_fd(), fd) } < 0 {
                let e = std::io::Error::last_os_error();
                for &done in &fds[..i] {
                    // SAFETY: as above. A failure leaves `done` on the pipe, which its drain
                    // keeps copying out until the pipe closes: nothing better to do.
                    unsafe { libc::dup2(saved.as_raw_fd(), done) };
                }
                // The drain is left to itself: with `write` dropped on return and every
                // descriptor put back, the pipe has no writer left, so it reads EOF and ends.
                return Err(e);
            }
        }
        Ok(Stream {
            fds,
            saved,
            drain: Some(drain),
        })
    }
}

/// A close-on-exec copy of `fd` numbered above the standard streams, so no dup2 onto one of
/// them closes it.
fn dup_above_std(fd: RawFd) -> std::io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor or -1.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `dup` was just returned to us and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

/// `fd`, moved above the standard streams if it is numbered as one of them.
fn above_std(fd: OwnedFd) -> std::io::Result<OwnedFd> {
    match fd.as_raw_fd() > libc::STDERR_FILENO {
        true => Ok(fd),
        false => dup_above_std(fd.as_raw_fd()),
    }
}

/// Copy `pipe` to `dest` until the pipe closes, or once `stop` is set: when the pipe has sat
/// empty for a poll, or [`STOP_WITHIN`] later at the most — children that inherited the stream
/// may hold the write end open for ever, and keep writing to it.
fn drain(mut pipe: File, mut dest: impl Write, stop: &AtomicBool) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut stopping: Option<Instant> = None;
    loop {
        if stop.load(Ordering::Acquire) {
            let since = *stopping.get_or_insert_with(Instant::now);
            if since.elapsed() >= STOP_WITHIN {
                return;
            }
        }
        let mut pfd = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one caller-owned pollfd, and the count matches.
        let ready = unsafe { libc::poll(&mut pfd, 1, IDLE_MS) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if ready == 0 {
            if stopping.is_some() {
                return;
            }
            continue;
        }
        match pipe.read(&mut buf) {
            Ok(0) => return,
            // Dropped rather than retried: a destination that refuses it is full, and holding
            // the output back would stall the writer once the pipe fills instead.
            Ok(n) => {
                let _ = dest.write_all(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Put the streams back first, so nothing written from here on lands in a pipe whose
        // drain is about to stop.
        for s in &self.streams {
            for &fd in &s.fds {
                // SAFETY: both descriptors are open; dup2 replaces `fd` atomically. A failure
                // leaves `fd` on the pipe, drained until the stop: nothing better to do.
                unsafe { libc::dup2(s.saved.as_raw_fd(), fd) };
            }
        }
        self.stop.store(true, Ordering::Release);
        for s in &mut self.streams {
            if let Some(drain) = s.drain.take() {
                let _ = drain.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A destination that refuses its first write, as a full filesystem would, then takes
    /// every write after it — space freed by a job that ended.
    struct RefusesFirst(bool, Arc<Mutex<Vec<u8>>>);

    impl Write for RefusesFirst {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(std::io::ErrorKind::StorageFull.into());
            }
            self.1.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The drain drops a chunk its destination refuses and passes the next one through, and
    /// stops once told to even though a writer still holds the pipe open.
    #[test]
    fn a_drain_drops_what_its_destination_refuses_and_stops_when_told() {
        let mut ends = [0; 2];
        // SAFETY: pipe2 writes two descriptors into the array we own, and only on success.
        assert_eq!(
            unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: both ends were just returned to us and nothing else owns them.
        let (read, mut write) = unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) };
        let got = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let drain = std::thread::spawn({
            let (stop, dest) = (Arc::clone(&stop), RefusesFirst(false, Arc::clone(&got)));
            move || drain(read, dest, &stop)
        });
        write.write_all(b"one\n").unwrap();
        // Written once the first chunk has been read, so the two arrive as separate reads.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut pending: libc::c_int = 0;
            // SAFETY: FIONREAD writes one c_int through the pointer to ours.
            unsafe { libc::ioctl(write.as_raw_fd(), libc::FIONREAD, &mut pending) };
            if pending == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "the drain never read");
            std::thread::sleep(Duration::from_millis(5));
        }
        write.write_all(b"two\n").unwrap();
        stop.store(true, Ordering::Release);
        // `write` is still open: only the stop can end the drain.
        drain.join().unwrap();
        drop(write);
        assert_eq!(&*got.lock().unwrap(), b"two\n");
    }

    /// Set in the child the tests below run, to what it should do.
    const CHILD: &str = "VK_OUTRELAY_TEST_CHILD";

    /// The relay's half of the tests below, run in a child with its streams where the parent
    /// put them — alone in its process, since the relay repoints the process's own streams.
    #[test]
    fn relayed_child() {
        let Some(mode) = std::env::var_os(CHILD) else {
            return;
        };
        if mode == "closed" {
            // Closed here rather than before exec: the Rust runtime reopens a standard stream
            // it starts without on /dev/null.
            // SAFETY: nothing in this process owns fd 2 as an OwnedFd.
            unsafe { libc::close(libc::STDERR_FILENO) };
        }
        let guard = relay();
        if mode == "closed" {
            // SAFETY: F_GETFD reads the descriptor's flags and nothing else.
            let flags = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETFD) };
            assert_eq!(flags, -1, "the relay reopened a closed stderr");
        }
        for i in 0..1000 {
            match i % 2 {
                0 => eprintln!("line {i}"),
                _ => println!("line {i}"),
            }
        }
        // A second relay while this one runs leaves it be.
        drop(relay());
        println!("line after a second relay");
        match mode.to_str() {
            // As the switch leaves on SIGTERM: no destructor runs past this.
            Some("exit") => {
                finish();
                std::process::exit(0);
            }
            Some("panic") => panic!("the last words"),
            _ => drop(guard),
        }
    }

    fn child(mode: &str, stdout: impl Into<std::process::Stdio>) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "outrelay::tests::relayed_child", "--nocapture"])
            .env(CHILD, mode)
            .stdout(stdout);
        cmd
    }

    fn run_child(
        mode: &str,
        stdout: impl Into<std::process::Stdio>,
        stderr: File,
    ) -> std::process::ExitStatus {
        child(mode, stdout).stderr(stderr).status().unwrap()
    }

    /// A log file of its own for one child's streams.
    fn child_log(mode: &str) -> (std::path::PathBuf, File) {
        let log = std::env::temp_dir().join(format!(
            "vk-outrelay-child-{mode}-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&log)
            .unwrap();
        (log, file)
    }

    fn relayed_lines(text: &str) -> Vec<&str> {
        text.lines().filter(|l| l.starts_with("line ")).collect()
    }

    /// A process printing through the relay is not killed by a stderr that refuses every write,
    /// and streams sharing one file get every line in the order it was printed, the last
    /// included — whether the process returns or leaves by `exit` after [`finish`].
    #[test]
    fn a_relayed_process_survives_a_full_stderr() {
        // stdout stays writable: the test harness in the child prints to it before the relay
        // starts, and would die of that itself.
        let full = File::options().write(true).open("/dev/full").unwrap();
        assert!(
            run_child("return", std::process::Stdio::null(), full).success(),
            "the child died printing to a full stderr"
        );

        let mut want: Vec<String> = (0..1000).map(|i| format!("line {i}")).collect();
        want.push("line after a second relay".into());
        for mode in ["return", "exit"] {
            let (log, file) = child_log(mode);
            assert!(run_child(mode, file.try_clone().unwrap(), file).success());
            let text = std::fs::read_to_string(&log).unwrap();
            let _ = std::fs::remove_file(&log);
            assert_eq!(
                relayed_lines(&text),
                want,
                "{mode}: lines lost or out of order"
            );
        }
    }

    /// A panic unwinding past the guard reaches the log, message and all.
    #[test]
    fn a_panic_past_the_guard_is_logged() {
        let (log, file) = child_log("panic");
        assert!(!run_child("panic", file.try_clone().unwrap(), file).success());
        let text = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        assert!(text.contains("the last words"), "{text}");
        assert_eq!(relayed_lines(&text).len(), 1001, "{text}");
    }

    /// With stderr closed, stdout is still relayed whole and stderr stays closed.
    #[test]
    fn a_closed_stderr_is_left_closed() {
        let (log, file) = child_log("closed");
        let mut cmd = child("closed", file);
        assert!(cmd.status().unwrap().success());
        let text = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        let mut want: Vec<String> = (1..1000).step_by(2).map(|i| format!("line {i}")).collect();
        want.push("line after a second relay".into());
        assert_eq!(relayed_lines(&text), want);
    }
}
