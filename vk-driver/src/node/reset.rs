//! Resetting a node: once it has drained, stop whatever this user still runs from past jobs,
//! clear what they left, validate, and return to the state the node was in.
//!
//! What is cleared is what a job leaves behind, and nothing a job needs to run faster next
//! time unless asked: the job dirs under `<state_dir>/jobs` (whatever a failed cleanup kept —
//! overlays, logs, sockets, a network lease) and the host checkouts no job uses; the
//! materialized images under `<state_dir>/{registry,docker,build}` only with `images`. The
//! build cache's registry store is never touched. An entry of `<state_dir>/jobs` that is not a
//! directory, a symlink included, is removed as itself and never followed. Validation is an
//! update's: `vk check`'s gate and `[node] validate`, then a session with the hub. A node that
//! does not pass stays drained, for an operator to look at, rather than take jobs.
//!
//! What is stopped is what the executor starts for a job and nothing else: a process of this
//! user whose binary is a `vk` — this one, the installed one, a release under the node dir, or
//! any file named `vk` — a `cloud-hypervisor` or a `virtiofsd`, and whose arguments name a
//! path inside one of the job dirs, whole or as a `--flag=<path>` value. A shell or a `tail` of
//! a job's log is left alone. Each is held by a pidfd opened before it is looked at and
//! signalled through it, and kept only if it is still alive once looked at: the pid was its
//! own throughout, so a pid reused meanwhile is never hit. One that outlives `SIGKILL` fails
//! the reset before anything is removed.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use vk_hub_proto::{NodeState, Outcome, UpdatePhase};

use super::core::Core;
use super::state::Work;
use crate::config::Config;

/// How long what is signalled has to exit before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// How long what is killed has to exit before the reset fails, its job dirs left.
const KILL_WAIT: Duration = Duration::from_secs(5);

/// How long a validated node waits for a session with the hub before the reset fails.
const HUB_WAIT: Duration = Duration::from_secs(600);

/// Carry the reset under way through `state`: clear in maintenance, then validate.
pub async fn run(core: &Core, cfg: &Arc<Config>, state: NodeState) {
    let images = match core.persisted().job.map(|j| j.work) {
        Some(Work::Reset { images }) => images,
        _ => return,
    };
    let ended = if state == NodeState::Maintenance {
        let clearing = cfg.clone();
        let ours = Binaries::of(core);
        let cleared = tokio::task::spawn_blocking(move || clear(&clearing, images, &ours))
            .await
            .map_err(|e| anyhow!("clearing the node: {e}"))
            .and_then(|r| r);
        match cleared {
            Ok(said) => {
                say!("reset: {said}; validating");
                core.change(|p| p.state = NodeState::Validating)
            }
            Err(e) => {
                say!("the reset failed: {e:#}");
                stay_drained(core, format!("{e:#}"))
            }
        }
    } else {
        match validated(core, cfg).await {
            Ok(()) => {
                say!("reset: validated");
                core.change(|p| {
                    p.end_job(Outcome::Done, UpdatePhase::Done);
                })
            }
            Err(why) => {
                say!("the reset's validation failed: {why}");
                stay_drained(core, why)
            }
        }
    };
    if let Err(e) = ended {
        say!("{e:#}");
    }
}

/// `vk check`'s gate and `[node] validate`, then a session with the hub.
async fn validated(core: &Core, cfg: &Arc<Config>) -> Result<(), String> {
    super::update::validate(cfg)
        .await
        .map_err(|why| format!("validation failed: {why}"))?;
    let mut connected = core.connected();
    match tokio::time::timeout(HUB_WAIT, connected.wait_for(|&up| up)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err(format!(
            "the hub was not reached within {}s of validating",
            HUB_WAIT.as_secs()
        )),
    }
}

/// End the reset as failed with `message`, the node left drained.
fn stay_drained(core: &Core, message: String) -> Result<()> {
    core.change(|p| {
        p.end_job_in(
            Outcome::Failed { message },
            UpdatePhase::Failed,
            Some(NodeState::Drained),
        );
    })
}

/// The binaries whose processes a reset may stop beside those named `vk`, `cloud-hypervisor`
/// and `virtiofsd`, by device and inode.
struct Binaries(HashSet<(u64, u64)>);

impl Binaries {
    /// This `vk`, the installed one, and every release under the node dir.
    fn of(core: &Core) -> Self {
        let mut files = vec![PathBuf::from("/proc/self/exe")];
        files.extend(core.persisted().installed);
        if let Ok(releases) = std::fs::read_dir(core.dir().join("releases")) {
            files.extend(releases.filter_map(Result::ok).map(|e| e.path()));
        }
        Binaries(
            files
                .iter()
                .filter_map(|f| std::fs::metadata(f).ok())
                .map(|m| (m.dev(), m.ino()))
                .collect(),
        )
    }

    /// Whether process `pid` runs one of them.
    fn cover(&self, pid: i32) -> bool {
        let exe = format!("/proc/{pid}/exe");
        // The file the process runs, deleted or not: the link is magic, not a path.
        if std::fs::metadata(&exe).is_ok_and(|m| self.0.contains(&(m.dev(), m.ino()))) {
            return true;
        }
        let Ok(path) = std::fs::read_link(&exe) else {
            return false;
        };
        let bytes = path.as_os_str().as_encoded_bytes();
        let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
        let name = bytes.rsplit(|&b| b == b'/').next();
        matches!(name, Some(b"vk" | b"cloud-hypervisor" | b"virtiofsd"))
    }
}

/// Stop past jobs' leftovers, release their network leases, and remove their dirs and idle
/// host checkouts. With `images`, also sweep materialized images. Return a text summary.
fn clear(cfg: &Config, images: bool, ours: &Binaries) -> Result<String> {
    let jobs = cfg.state_dir().join("jobs");
    let JobsDir { dirs, strays } = job_dirs(&jobs)?;
    let (stopped, survivors) = stop_leftovers(&dirs, ours)?;
    if !survivors.is_empty() {
        let pids: Vec<_> = survivors.iter().map(i32::to_string).collect();
        anyhow::bail!(
            "pid {} still running after SIGKILL; nothing was removed",
            pids.join(", ")
        );
    }
    for stray in &strays {
        match std::fs::remove_file(stray) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", stray.display())),
        }
    }
    let mut removed = 0;
    for dir in &dirs {
        if let Some(id) = dir.file_name().and_then(|n| n.to_str()) {
            crate::net::release_lease(&jobs.join(".net"), dir, id);
        }
        match std::fs::remove_dir_all(dir) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", dir.display())),
        }
    }
    crate::checkout::gc_idle(&cfg.checkout_root(), Duration::ZERO);
    if images {
        let state = cfg.state_dir();
        let registry = state.join("registry");
        crate::image::gc_idle(&registry, Duration::ZERO);
        crate::image::sweep_chunks(&registry);
        for tier in ["docker", "build"] {
            crate::image::gc_idle(&state.join(tier), Duration::ZERO);
            crate::image::sweep_orphaned_build_tmp(&state.join(tier));
        }
    }
    // The sweeps say themselves what they evicted; a tree in use is left.
    Ok(format!(
        "stopped {stopped} process(es) left by past jobs, removed {removed} of {} job dir(s){}, \
         swept the host checkouts no job uses{}",
        dirs.len(),
        match strays.len() {
            0 => String::new(),
            n => format!(" and {n} other entr{}", if n == 1 { "y" } else { "ies" }),
        },
        if images {
            " and the materialized images"
        } else {
            ""
        }
    ))
}

/// What is under `<state_dir>/jobs` beside the dot-entries, which are shared state.
#[derive(Default)]
struct JobsDir {
    /// The job dirs: the directories, never followed through a symlink.
    dirs: Vec<PathBuf>,
    /// Anything else — a file, a symlink — removed as itself.
    strays: Vec<PathBuf>,
}

fn job_dirs(jobs: &Path) -> Result<JobsDir> {
    let entries = match std::fs::read_dir(jobs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(JobsDir::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", jobs.display())),
    };
    let mut out = JobsDir::default();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", jobs.display()))?;
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        let kind = entry
            .file_type()
            .with_context(|| format!("reading {}", entry.path().display()))?;
        if kind.is_dir() {
            out.dirs.push(entry.path());
        } else {
            out.strays.push(entry.path());
        }
    }
    Ok(out)
}

/// A process to stop, held by its pidfd.
struct Leftover {
    pid: i32,
    fd: OwnedFd,
}

impl Leftover {
    /// Process `pid`, held from now on whatever its pid comes to name.
    fn open(pid: i32) -> Option<Self> {
        // SAFETY: `pidfd_open` takes a pid and flags and returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let fd = i32::try_from(fd).ok().filter(|&fd| fd >= 0)?;
        // SAFETY: a fresh descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Some(Leftover { pid, fd })
    }

    fn signal(&self, signal: libc::c_int) {
        // SAFETY: `pidfd_send_signal` on a pidfd this value owns, with no siginfo. It fails
        // only for a process already gone, which is what is wanted.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }

    /// Whether it has exited, waiting up to `timeout` for it to.
    fn gone(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
            // SAFETY: one pollfd on the stack, for the duration of the call.
            let n = unsafe { libc::poll(&mut poll, 1, ms) };
            if n >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return n > 0;
            }
        }
    }
}

/// Signal what [`leftovers`] finds, and kill what has not exited after [`STOP_GRACE`]. How
/// many there were, and the pids of those still alive [`KILL_WAIT`] after being killed.
fn stop_leftovers(dirs: &[PathBuf], ours: &Binaries) -> Result<(usize, Vec<i32>)> {
    let found = leftovers(dirs, ours)?;
    for p in &found {
        p.signal(libc::SIGTERM);
    }
    let deadline = Instant::now() + STOP_GRACE;
    let mut survivors = Vec::new();
    for p in &found {
        if !p.gone(deadline.saturating_duration_since(Instant::now())) {
            say!(
                "reset: killing pid {}, still running {}s after it was told to stop",
                p.pid,
                STOP_GRACE.as_secs()
            );
            p.signal(libc::SIGKILL);
            if !p.gone(KILL_WAIT) {
                survivors.push(p.pid);
            }
        }
    }
    Ok((found.len(), survivors))
}

/// Whether one of `args` names a path inside one of `dirs`, whole or as the value of a
/// `--flag=`, compared as bytes and at a component boundary: `/jobs/12` is not inside
/// `/jobs/123`.
fn names_a_job_dir(args: &[u8], dirs: &[PathBuf]) -> bool {
    args.split(|&b| b == 0).any(|arg| {
        let value = arg
            .iter()
            .position(|&b| b == b'=')
            .and_then(|at| arg.get(at + 1..))
            .filter(|_| arg.starts_with(b"-"));
        [Some(arg), value].into_iter().flatten().any(|v| {
            dirs.iter().any(|d| {
                v.strip_prefix(d.as_os_str().as_encoded_bytes())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
            })
        })
    })
}

/// This user's processes of [`Binaries`] whose arguments name a job dir, each held by a pidfd
/// opened before it was looked at and alive after: what is held is what matched. A `/proc`
/// this process cannot list is an error: without it, nothing would be found and job dirs
/// would be removed under live processes.
fn leftovers(dirs: &[PathBuf], ours: &Binaries) -> Result<Vec<Leftover>> {
    if dirs.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let own = std::process::id();
    let procs = std::fs::read_dir("/proc").context("listing /proc to find what past jobs left")?;
    let matches = |pid: i32| -> bool {
        std::fs::metadata(format!("/proc/{pid}")).is_ok_and(|m| m.uid() == uid)
            && ours.cover(pid)
            && std::fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|args| names_a_job_dir(&args, dirs))
    };
    let mut out = Vec::new();
    for entry in procs.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if u32::try_from(pid).ok() == Some(own) {
            continue;
        }
        let Some(held) = Leftover::open(pid) else {
            continue;
        };
        // Alive once looked at, it held `pid` all along: what was read was its own.
        if matches(pid) && !held.gone(Duration::ZERO) {
            out.push(held);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a leftover job process is made of here: this test binary — a binary a reset
    /// stops, being the running `vk`'s own — waiting, with a job dir among its arguments.
    #[test]
    #[ignore = "a stand-in process for the reset tests, run by them"]
    fn stand_in() {
        std::thread::sleep(Duration::from_secs(60));
    }

    fn spawn_stand_in(arg: &Path) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "node::reset::tests::stand_in"])
            .arg(arg)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    fn ours() -> Binaries {
        let me = std::fs::metadata("/proc/self/exe").unwrap();
        Binaries(HashSet::from([(me.dev(), me.ino())]))
    }

    #[test]
    fn a_job_dir_is_named_whole_or_as_a_flag_s_value() {
        let dirs = vec![PathBuf::from("/s/jobs/123")];
        let named = |args: &[&str]| names_a_job_dir(args.join("\0").as_bytes(), &dirs);
        assert!(named(&["virtiofsd", "--socket-path=/s/jobs/123/vfsd.sock"]));
        assert!(named(&["vk", "gitlab", "supervise", "/s/jobs/123"]));
        assert!(named(&[
            "cloud-hypervisor",
            "--api-socket",
            "/s/jobs/123/api.sock"
        ]));
        assert!(!named(&["virtiofsd", "--shared-dir=/s/jobs/1234/root"]));
        assert!(!named(&["tail", "/s/jobs/12/log"]));
        assert!(!named(&["x=/s/jobs/123"]));
    }

    #[test]
    fn what_a_job_dir_left_running_is_stopped_and_the_dir_and_its_lease_removed() {
        let root = std::env::temp_dir().join(format!("vk-node-reset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let jobs = root.join("jobs");
        for d in ["123", "12", ".net"] {
            std::fs::create_dir_all(jobs.join(d)).unwrap();
        }
        std::fs::write(jobs.join("123").join("net.lease"), "vk3\n").unwrap();
        std::fs::write(jobs.join(".net").join("vk3.lock"), "123").unwrap();
        std::fs::write(jobs.join(".net").join("vk4.lock"), "999").unwrap();
        let mut child = spawn_stand_in(&jobs.join("123").join("sock"));
        // A process of another binary naming the job dir — a shell, a tail — is left.
        let mut shell = std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 1; done"])
            .arg(jobs.join("123"))
            .spawn()
            .unwrap();
        let only_12 = vec![jobs.join("12")];
        assert!(leftovers(&only_12, &ours()).unwrap().is_empty());
        let dirs = job_dirs(&jobs).unwrap().dirs;
        assert_eq!(dirs.len(), 2);
        let found = leftovers(&dirs, &ours()).unwrap();
        assert_eq!(
            found.iter().map(|l| l.pid).collect::<Vec<_>>(),
            [i32::try_from(child.id()).unwrap()]
        );
        drop(found);
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", root.display().to_string())).unwrap();
        let said = clear(&cfg, false, &ours()).unwrap();
        assert!(said.contains("stopped 1 process"), "{said}");
        assert!(said.contains("removed 2 of 2 job dir(s)"), "{said}");
        child.wait().unwrap();
        assert!(shell.try_wait().unwrap().is_none());
        shell.kill().unwrap();
        shell.wait().unwrap();
        let mut left: Vec<_> = std::fs::read_dir(&jobs)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, [".net"]);
        // Its tap's lock is given back; another job's is not touched.
        let locks: Vec<_> = std::fs::read_dir(jobs.join(".net"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(locks, ["vk4.lock"]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn what_is_not_a_job_dir_is_removed_as_itself_and_never_followed() {
        let root = std::env::temp_dir().join(format!("vk-node-reset-odd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let jobs = root.join("state").join("jobs");
        std::fs::create_dir_all(jobs.join(".net")).unwrap();
        // A symlink to a dir outside, holding a lease whose lock names the link.
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("net.lease"), "vk5\n").unwrap();
        std::fs::write(jobs.join(".net").join("vk5.lock"), "link").unwrap();
        std::os::unix::fs::symlink(&outside, jobs.join("link")).unwrap();
        std::fs::write(jobs.join("stray"), "").unwrap();
        // A lease naming a path out of the locks dir.
        std::fs::create_dir_all(jobs.join("55")).unwrap();
        std::fs::write(jobs.join("55").join("net.lease"), "../../escape\n").unwrap();
        std::fs::write(root.join("state").join("escape.lock"), "55").unwrap();
        let cfg: Config = toml::from_str(&format!(
            "state_dir = {:?}\n",
            root.join("state").display().to_string()
        ))
        .unwrap();
        let said = clear(&cfg, false, &ours()).unwrap();
        assert!(
            said.contains("removed 1 of 1 job dir(s) and 2 other entries"),
            "{said}"
        );
        let mut left: Vec<_> = std::fs::read_dir(&jobs)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, [".net"]);
        assert!(root.join("state").join("escape.lock").exists());
        assert!(outside.join("net.lease").exists());
        assert!(jobs.join(".net").join("vk5.lock").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// With `images`, an idle materialized image is evicted and one in use kept.
    #[test]
    fn images_are_evicted_only_when_asked_and_only_when_idle() {
        let root = std::env::temp_dir().join(format!("vk-node-reset-img-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let state = root.join("state");
        let base = |fp: &str| {
            let dir = state.join("build").join(fp);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("runner.ext4"), "").unwrap();
            crate::image::mark_used(&dir);
            dir
        };
        let idle = base("idle");
        let busy = base("busy");
        let _use = crate::image::acquire_use_lock_for(&state, &busy.join("runner.ext4"))
            .unwrap()
            .unwrap();
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", state.display().to_string())).unwrap();
        clear(&cfg, false, &ours()).unwrap();
        assert!(idle.exists());
        // Retried: a test forking meanwhile can hold the image's lock for an instant.
        assert!(crate::cachelock::reclaimed_eventually(|| {
            clear(&cfg, true, &ours()).unwrap();
            !idle.exists()
        }));
        assert!(busy.join("runner.ext4").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// An exited process still held is not a leftover: its pid may name another by now.
    #[test]
    fn a_process_gone_once_looked_at_is_not_held() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let held = Leftover::open(pid).unwrap();
        child.wait().unwrap();
        assert!(held.gone(Duration::ZERO));
        // Signalling what has gone is harmless.
        held.signal(libc::SIGTERM);
    }
}
