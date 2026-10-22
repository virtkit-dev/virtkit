//! The `vk gc` pass the commands that fill the caches start in the background: at most every
//! `[gc] interval_hours`, and sooner when the data dir's filesystem runs below `[gc] min_free`.
//! Only a command starts one, so a host nobody uses is never swept, and a pass never stands in
//! for the room a job is admitted against (that is `image::evict_for_room`'s).
//!
//! The command pays for the check: three `stat`s and one `statvfs`. Everything else happens in
//! the child, `vk gc --auto`, in a session of its own, its output appended to
//! `<data dir>/gc.log`. It keeps the command's priority wherever it holds a lock a build or a
//! boot may be waiting on — the build cache's store, an environment's, a run dir's, an image's
//! — which is nearly everywhere; only its reading of the build cache under the shared lock,
//! the slow part, runs at the lowest CPU and I/O priority, on a thread of its own
//! ([`lower_planning`]), as the lowering of a thread's priority cannot be undone.

use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use crate::config::Config;

/// Dated by every pass that ran to its end: what the interval counts from.
const DONE: &str = ".gc-done";
/// Dated by every pass a command started, before it starts it: what keeps two commands from
/// starting one each, and a failing pass from being started by every command.
const STARTED: &str = ".gc-started";
/// Dated by a pass that was short of space and could not get back above the floor: what
/// keeps every command from starting another such pass at once.
const SHORT: &str = ".gc-short";
/// Held by the pass that runs, so a second one finds it held and leaves, and a manual one
/// waits for it.
pub(crate) const LOCK: &str = ".gc.lock";
const LOG: &str = "gc.log";
/// The least time between two passes started, whatever started them.
const RETRY: Duration = Duration::from_secs(600);
/// The least time after a pass that could not get back above the floor before being short of
/// space starts another.
const SHORT_BACKOFF: Duration = Duration::from_secs(3600);
/// How far in the future a stamp may be dated before it is taken for a clock set back and
/// ignored, rather than holding off every pass until the clock catches up.
const SKEW: Duration = Duration::from_secs(60);
/// Past this size, the log starts over when the next pass is started.
const LOG_MAX: u64 = 1 << 20;

/// Why a pass is due.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Due {
    Interval,
    /// `avail` bytes are free, under the `floor`.
    Pressure {
        avail: u64,
        floor: u64,
    },
}

/// Previous pass timestamps, read before deciding whether another pass is due.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Stamps {
    /// The last pass that ran to its end.
    pub(crate) done: Option<SystemTime>,
    /// The last pass a command started.
    pub(crate) started: Option<SystemTime>,
    /// The last pass that stayed short of space.
    pub(crate) short: Option<SystemTime>,
}

/// Whether a pass is due at `now`: the last started more than [`RETRY`] ago, and either the
/// filesystem below `floor` — unless a pass short of space within [`SHORT_BACKOFF`] could not
/// help — or the last finished more than `interval` ago (or never). A stamp more than [`SKEW`]
/// in the future is ignored.
pub(crate) fn due(
    now: SystemTime,
    stamps: Stamps,
    interval: Option<Duration>,
    avail: Option<u64>,
    floor: Option<u64>,
) -> Option<Due> {
    let valid = |t: Option<SystemTime>| t.filter(|&t| t <= now + SKEW);
    let within = |t: Option<SystemTime>, window: Duration| {
        valid(t).is_some_and(|t| now.duration_since(t).unwrap_or_default() < window)
    };
    if within(stamps.started, RETRY) {
        return None;
    }
    if let (Some(avail), Some(floor)) = (avail, floor)
        && avail < floor
        && !within(stamps.short, SHORT_BACKOFF)
    {
        return Some(Due::Pressure { avail, floor });
    }
    let interval = interval?;
    (!within(stamps.done, interval)).then_some(Due::Interval)
}

/// Start a background pass over `state_dir` if one is due, unless `[gc] auto = false` or
/// `VK_GC_AUTO=0`. Best-effort: a pass that cannot be started is tried again by a later
/// command.
pub(crate) fn maybe_start(cfg: &Config, state_dir: &Path) {
    if !cfg.gc.auto() || std::env::var_os("VK_GC_AUTO").is_some_and(|v| v == "0") {
        return;
    }
    let mtime = |name: &str| {
        std::fs::symlink_metadata(state_dir.join(name))
            .and_then(|m| m.modified())
            .ok()
    };
    // No data dir yet: nothing to collect.
    let Ok(space) = crate::usage::fs_space(state_dir) else {
        return;
    };
    let now = SystemTime::now();
    let floor = cfg.gc.min_free(space.total);
    let stamps = Stamps {
        done: mtime(DONE),
        started: mtime(STARTED),
        short: mtime(SHORT),
    };
    let Some(why) = due(now, stamps, cfg.gc.interval(), Some(space.avail), floor) else {
        return;
    };
    if let Err(e) = start(cfg, state_dir, now) {
        if matches!(why, Due::Pressure { .. }) {
            eprintln!("virtkit: starting a background `vk gc`: {e:#}");
        }
        return;
    }
    if let Due::Pressure { avail, floor } = why {
        eprintln!(
            "virtkit: {} free under {}, below the {} vk keeps free: reclaiming unused caches \
             in the background (`vk gc`, log {})",
            crate::usage::fmt_bytes(avail),
            state_dir.display(),
            crate::usage::fmt_bytes(floor),
            state_dir.join(LOG).display()
        );
    }
}

/// Claim the attempt — [`STARTED`], locked and dated again under the lock, so of two commands
/// due at once only one starts a pass — then start `vk gc --auto` with this command's config.
fn start(cfg: &Config, state_dir: &Path, now: SystemTime) -> anyhow::Result<()> {
    use anyhow::Context;

    let claim = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir.join(STARTED))
        .context("claiming the pass")?;
    // SAFETY: the fd is owned by `claim`, open across the call; LOCK_NB never waits.
    if unsafe { libc::flock(claim.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        anyhow::bail!("another command is starting one");
    }
    let started = claim
        .metadata()
        .and_then(|m| m.modified())
        .ok()
        .filter(|&t| t <= now + SKEW);
    let fresh = claim.metadata().is_ok_and(|m| m.len() > 0)
        && started.is_some_and(|t| now.duration_since(t).unwrap_or_default() < RETRY);
    if fresh {
        anyhow::bail!("another command has just started one");
    }
    // Non-empty once claimed, so a file just created by this open is not mistaken for a claim.
    claim.set_len(1).context("claiming the pass")?;
    claim.set_modified(now).context("claiming the pass")?;

    let log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir.join(LOG))
        .context("opening the gc log")?;
    if log.metadata().is_ok_and(|m| m.len() > LOG_MAX) {
        log.set_len(0).context("truncating the gc log")?;
    }
    let mut cmd = Command::new(crate::spawn::self_exe());
    if let Some(path) = &cfg.source {
        cmd.arg("--config").arg(path);
    }
    cmd.args(["gc", "--auto"])
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("opening the gc log")?)
        .stderr(log);
    // SAFETY: the hook runs in the forked child between fork and exec, and makes only
    // async-signal-safe system calls.
    unsafe {
        cmd.pre_exec(|| {
            detach_child();
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("spawning `vk gc --auto`")?;
    // Reaped here rather than left a zombie for as long as this command runs, a VM's
    // controller for days; once this process exits, init reaps it instead.
    std::thread::Builder::new()
        .name("vk-gc-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        })
        .context("starting the gc reaper")?;
    Ok(())
}

/// Lower the calling thread to the lowest CPU priority and the lowest best-effort I/O
/// priority, for good: the reading of the build cache a background pass does under the shared
/// lock, which builds share (see `vk_registry::GcPolicy::lower_planning`). Not the idle I/O
/// class, which a busy disk would starve outright.
pub(crate) fn lower_planning() {
    const IOPRIO_WHO_PROCESS: libc::c_int = 1;
    const IOPRIO_BE_LOWEST: libc::c_int = (2 << 13) | 7;
    // SAFETY: both act on the calling thread alone (`0` names it); a failure leaves it as it was.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0,
            IOPRIO_BE_LOWEST,
        );
    }
}

/// In the child before exec: a session of its own, so the terminal's signals and a VM
/// controller's process group pass it by; and no descriptor past stdio kept across the exec —
/// `vk` holds some open without `O_CLOEXEC`, a `--detach` readiness pipe among them, whose
/// reader would otherwise wait for the pass to end.
fn detach_child() {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
    // SAFETY: setsid, close_range, getrlimit and fcntl are async-signal-safe system calls on
    // this process's own state; failures leave it as it was.
    unsafe {
        libc::setsid();
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
            // Before Linux 5.11: mark them one by one, up to the most this process may open.
            let mut limit: libc::rlimit = std::mem::zeroed();
            let top = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                libc::c_int::try_from(limit.rlim_cur.min(1 << 20)).unwrap_or(1 << 20)
            } else {
                1024
            };
            for fd in 3..top {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
        }
    }
}

/// How long a manual `vk gc` waits for a background pass to finish.
pub(crate) const MANUAL_WAIT: Duration = Duration::from_secs(60);

/// What [`lock`] got.
pub(crate) enum Pass {
    /// [`LOCK`], held for the pass.
    Held { _lock: std::fs::File },
    /// Another pass holds it, past the wait.
    Busy,
    /// It cannot be opened, which a manual pass goes on without.
    Unlocked,
}

/// Hold [`LOCK`] for a pass, waiting up to `wait` for the one holding it: none for
/// `vk gc --auto`, which leaves; [`MANUAL_WAIT`] for a manual `vk gc`, saying so.
pub(crate) fn lock(state_dir: &Path, wait: Duration) -> Pass {
    let Ok(file) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir.join(LOCK))
    else {
        return Pass::Unlocked;
    };
    let deadline = std::time::Instant::now() + wait;
    let mut said = false;
    loop {
        // SAFETY: the fd is owned by `file`, open across the call; LOCK_NB never waits.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Pass::Held { _lock: file };
        }
        if std::time::Instant::now() >= deadline {
            return Pass::Busy;
        }
        if !said {
            eprintln!("virtkit: gc: waiting for the background pass to finish");
            said = true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The log a background pass appends to under `state_dir`.
pub(crate) fn log_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join(LOG)
}

/// Date a pass that ran to its end, for the next interval to count from — not one that left a
/// category for the next — and say whether it is still `short` of space after a pass that tried
/// to free it, which holds off the next such pass for [`SHORT_BACKOFF`].
pub(crate) fn finished(state_dir: &Path, complete: bool, short: Option<bool>) {
    let date = |name: &str| {
        let stamp = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_dir.join(name));
        if let Ok(f) = stamp {
            let _ = f.set_modified(SystemTime::now());
        }
    };
    if complete {
        date(DONE);
    }
    match short {
        Some(true) => date(SHORT),
        // Best-effort: a stale one only holds the next pressure pass off for a while.
        Some(false) => {
            let _ = std::fs::remove_file(state_dir.join(SHORT));
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_is_due_on_its_interval_or_under_pressure_but_not_twice_in_a_row() {
        let now = SystemTime::now();
        let ago = |s: u64| Some(now - Duration::from_secs(s));
        let ahead = |s: u64| Some(now + Duration::from_secs(s));
        let day = Some(Duration::from_secs(86_400));
        let gib = 1u64 << 30;
        let stamps = |done, started, short| Stamps {
            done,
            started,
            short,
        };
        let pressure = Some(Due::Pressure {
            avail: gib / 2,
            floor: gib,
        });
        // Never run: due.
        assert_eq!(
            due(now, Stamps::default(), day, Some(50 * gib), Some(gib)),
            Some(Due::Interval)
        );
        // Run an hour ago: not due; a day ago: due.
        let hour_ago = stamps(ago(3600), ago(3600), None);
        assert_eq!(due(now, hour_ago, day, None, None), None);
        let day_ago = stamps(ago(90_000), ago(90_000), None);
        assert_eq!(due(now, day_ago, day, None, None), Some(Due::Interval));
        // Short of space: due whatever the interval, and with none at all...
        assert_eq!(due(now, hour_ago, day, Some(gib / 2), Some(gib)), pressure);
        assert_eq!(due(now, hour_ago, None, Some(gib / 2), Some(gib)), pressure);
        // ... but not within minutes of the last one started, which may still be running or
        // may have failed...
        let just_started = stamps(ago(90_000), ago(60), None);
        assert_eq!(due(now, just_started, day, Some(gib / 2), Some(gib)), None);
        // ... nor within the hour of one that could not get back above the floor, which
        // leaves the interval to decide.
        let short = stamps(ago(3600), ago(1200), ago(1200));
        assert_eq!(due(now, short, day, Some(gib / 2), Some(gib)), None);
        let short = stamps(ago(90_000), ago(1200), ago(1200));
        assert_eq!(
            due(now, short, day, Some(gib / 2), Some(gib)),
            Some(Due::Interval)
        );
        let short_long_ago = stamps(ago(3600), ago(7200), ago(7200));
        assert_eq!(
            due(now, short_long_ago, day, Some(gib / 2), Some(gib)),
            pressure
        );
        // A stamp dated well in the future is a clock set back: ignored, not obeyed; a few
        // seconds ahead is the clock's grain, and counts.
        let future = stamps(ahead(3600), ahead(3600), None);
        assert_eq!(due(now, future, day, None, None), Some(Due::Interval));
        let skewed = stamps(ahead(5), ahead(5), None);
        assert_eq!(due(now, skewed, day, None, None), None);
        // No interval and room enough: never.
        assert_eq!(
            due(now, Stamps::default(), None, Some(50 * gib), Some(gib)),
            None
        );
    }

    /// The child keeps no descriptor of its parent's past stdio: a readiness pipe the parent
    /// holds without `O_CLOEXEC` is not the child's to keep open.
    #[test]
    fn the_child_keeps_none_of_its_parents_descriptors() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: plain pipe(2) into a local array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "ls /proc/self/fd"]).stdout(Stdio::piped());
        // SAFETY: as in `start`.
        unsafe {
            cmd.pre_exec(|| {
                detach_child();
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        // SAFETY: the descriptors are this test's own.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let listed: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect();
        for fd in fds {
            assert!(!listed.contains(&fd.to_string()), "{fd} in {listed:?}");
        }
    }

    /// Of two commands due at once, one starts the pass; a pass holds its lock against a
    /// second one.
    #[test]
    fn the_claim_and_the_lock_let_one_through() {
        let dir = std::env::temp_dir().join(format!("vk-autogc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let Pass::Held { _lock: held } = lock(&dir, Duration::ZERO) else {
            panic!("a free lock is taken");
        };
        assert!(
            matches!(lock(&dir, Duration::ZERO), Pass::Busy),
            "a held lock is not"
        );
        let began = std::time::Instant::now();
        assert!(matches!(lock(&dir, Duration::from_millis(500)), Pass::Busy));
        assert!(
            began.elapsed() >= Duration::from_millis(500),
            "a wait is waited out"
        );
        drop(held);
        assert!(matches!(lock(&dir, Duration::ZERO), Pass::Held { .. }));

        // A pass short of space dates it, one back above the floor clears it, and only a
        // complete one dates the interval.
        finished(&dir, false, Some(true));
        assert!(!dir.join(DONE).exists() && dir.join(SHORT).exists());
        finished(&dir, true, Some(false));
        assert!(dir.join(DONE).exists() && !dir.join(SHORT).exists());

        // A claim dated now is fresh: a second start refuses before spawning anything.
        let claim = dir.join(STARTED);
        std::fs::write(&claim, b"x").unwrap();
        let cfg = Config::default();
        let err = start(&cfg, &dir, SystemTime::now())
            .unwrap_err()
            .to_string();
        assert!(err.contains("just started"), "{err}");
        assert!(!dir.join(LOG).exists(), "nothing was started");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
