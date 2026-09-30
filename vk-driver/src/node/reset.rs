//! Resetting a node: once it has drained, stop whatever this user still runs from past jobs,
//! clear what they left, validate, and return to the state the node was in. See
//! `docs/fleet-design.md`, "Resets".
//!
//! What is cleared is what a job leaves behind, and nothing a job needs to run faster next
//! time unless asked: the job dirs under `<state_dir>/jobs` (whatever a failed cleanup kept —
//! overlays, logs, sockets) and the host checkouts; the materialized images under
//! `<state_dir>/{registry,docker,build}` only with `images`. The build cache's registry store
//! is never touched. A node that does not pass validation afterwards stays drained, for an
//! operator to look at, rather than take jobs.
//!
//! What is stopped is what the executor starts for a job and nothing else: a process whose
//! binary is `vk` — the installed one, one under the node dir, or any named `vk` — a
//! `cloud-hypervisor` or a `virtiofsd`, and whose arguments name a path inside one of the job
//! dirs, whole or as a `--flag=<path>` value. A shell or a `tail` of a job's log is left alone.
//! Each is signalled through a pidfd opened while it was seen to match, so a pid reused
//! between the scan and the signal is never hit.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use vk_fleet_proto::{NodeState, Outcome, UpdatePhase};

use super::core::Core;
use super::state::Work;
use crate::config::Config;

/// How long what is signalled has to exit before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// Carry the reset under way through `state`: clear in maintenance, then validate.
pub async fn run(core: &Core, cfg: &Arc<Config>, state: NodeState) {
    let images = match core.persisted().job.map(|j| j.work) {
        Some(Work::Reset { images }) => images,
        _ => return,
    };
    if state == NodeState::Maintenance {
        let clearing = cfg.clone();
        let ours = Binaries {
            installed: core.persisted().installed,
            node_dir: core.dir().to_path_buf(),
        };
        let cleared = tokio::task::spawn_blocking(move || clear(&clearing, images, &ours))
            .await
            .map_err(|e| anyhow::anyhow!("clearing the node: {e}"))
            .and_then(|r| r);
        let next = match cleared {
            Ok(said) => {
                eprintln!("vk node: reset: {said}; validating");
                core.change(|p| p.state = NodeState::Validating)
            }
            Err(e) => {
                eprintln!("vk node: the reset failed: {e:#}");
                let message = format!("{e:#}");
                core.change(|p| {
                    p.end_job_in(
                        Outcome::Failed { message },
                        UpdatePhase::Failed,
                        Some(NodeState::Drained),
                    );
                })
            }
        };
        if let Err(e) = next {
            eprintln!("vk node: {e:#}");
        }
        return;
    }
    let ended = match super::update::validate(cfg).await {
        Ok(()) => {
            eprintln!("vk node: reset: validated");
            core.change(|p| {
                p.end_job(Outcome::Done, UpdatePhase::Done);
            })
        }
        Err(why) => {
            eprintln!("vk node: the reset's validation failed: {why}");
            core.change(|p| {
                p.end_job_in(
                    Outcome::Failed {
                        message: format!("validation failed: {why}"),
                    },
                    UpdatePhase::Failed,
                    Some(NodeState::Drained),
                );
            })
        }
    };
    if let Err(e) = ended {
        eprintln!("vk node: {e:#}");
    }
}

/// The binaries whose processes a reset may stop, beside those named `cloud-hypervisor` and
/// `virtiofsd`: `vk` as installed, as run from the node dir, or by that name.
pub struct Binaries {
    pub installed: Option<PathBuf>,
    pub node_dir: PathBuf,
}

impl Binaries {
    fn cover(&self, pid: i32) -> bool {
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            return false;
        };
        let bytes = exe.as_os_str().as_encoded_bytes();
        let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
        let exe = Path::new(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(bytes));
        let name = exe.file_name().map(|n| n.as_encoded_bytes());
        matches!(name, Some(b"vk" | b"cloud-hypervisor" | b"virtiofsd"))
            || exe.starts_with(&self.node_dir)
            || self.installed.as_deref() == Some(exe)
            || same_file(exe, Path::new("/proc/self/exe"))
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Stop what past jobs left running, give back their network leases, remove their dirs and
/// the host checkouts no job uses — and the materialized images with `images`. What was
/// done, in words.
fn clear(cfg: &Config, images: bool, ours: &Binaries) -> Result<String> {
    let jobs = cfg.state_dir().join("jobs");
    let dirs = job_dirs(&jobs)?;
    let stopped = stop_leftovers(&dirs, ours)?;
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
    let state = cfg.state_dir();
    if images {
        let registry = state.join("registry");
        crate::image::gc_idle(&registry, Duration::ZERO);
        crate::image::sweep_chunks(&registry);
        for tier in ["docker", "build"] {
            crate::image::gc_idle(&state.join(tier), Duration::ZERO);
            crate::image::sweep_orphaned_build_tmp(&state.join(tier));
        }
    }
    // The sweeps say themselves what they evicted; a tree in use, or one that would not go, is
    // left and not counted here.
    Ok(format!(
        "stopped {stopped} process(es) left by past jobs, removed {removed} of {} job dir(s), \
         swept the host checkouts no job uses{}",
        dirs.len(),
        if images {
            " and the materialized images"
        } else {
            ""
        }
    ))
}

/// The job dirs under `jobs`: every entry but the dot-directories, which are shared state.
fn job_dirs(jobs: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(jobs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", jobs.display())),
    };
    Ok(entries
        .filter_map(Result::ok)
        .filter(|e| !e.file_name().as_encoded_bytes().starts_with(b"."))
        .map(|e| e.path())
        .collect())
}

/// A process to stop, held by its pidfd.
struct Leftover {
    pid: i32,
    fd: std::os::fd::OwnedFd,
}

impl Leftover {
    fn signal(&self, signal: libc::c_int) {
        use std::os::fd::AsRawFd;
        // SAFETY: `pidfd_send_signal` on a pidfd this value owns, with no siginfo.
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
        use std::os::fd::AsRawFd;
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one pollfd on the stack, for the duration of the call.
        unsafe { libc::poll(&mut poll, 1, ms) > 0 }
    }
}

/// Signal what [`leftovers`] finds, and kill what has not exited after [`STOP_GRACE`]. How
/// many there were.
fn stop_leftovers(dirs: &[PathBuf], ours: &Binaries) -> Result<usize> {
    let found = leftovers(dirs, ours)?;
    for p in &found {
        p.signal(libc::SIGTERM);
    }
    let deadline = Instant::now() + STOP_GRACE;
    for p in &found {
        if !p.gone(deadline.saturating_duration_since(Instant::now())) {
            eprintln!(
                "vk node: reset: killing pid {}, still running after {STOP_GRACE:?}",
                p.pid
            );
            p.signal(libc::SIGKILL);
            p.gone(Duration::from_secs(5));
        }
    }
    Ok(found.len())
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

/// This user's processes of [`Binaries`] whose arguments name a job dir, each held by a
/// pidfd opened and then checked again, so what is held is what matched. A `/proc` this
/// process cannot list — `hidepid`, a sandbox — is an error: without it, nothing would be
/// found and job dirs would be removed under live processes.
fn leftovers(dirs: &[PathBuf], ours: &Binaries) -> Result<Vec<Leftover>> {
    use std::os::fd::FromRawFd;
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
        if u32::try_from(pid).ok() == Some(own) || !matches(pid) {
            continue;
        }
        // SAFETY: `pidfd_open` takes a pid and flags and returns a descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let Ok(fd) = i32::try_from(fd) else { continue };
        if fd < 0 {
            continue;
        }
        // SAFETY: a fresh descriptor this call owns.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        // Checked again with the pidfd held: the pid is now this process's for good.
        if matches(pid) {
            out.push(Leftover { pid, fd });
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

    fn ours(root: &Path) -> Binaries {
        Binaries {
            installed: None,
            node_dir: root.join("node"),
        }
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
        assert!(leftovers(&only_12, &ours(&root)).unwrap().is_empty());
        let dirs = job_dirs(&jobs).unwrap();
        assert_eq!(dirs.len(), 2);
        let found = leftovers(&dirs, &ours(&root)).unwrap();
        assert_eq!(
            found.iter().map(|l| l.pid).collect::<Vec<_>>(),
            [i32::try_from(child.id()).unwrap()]
        );
        drop(found);
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", root.display().to_string())).unwrap();
        let said = clear(&cfg, false, &ours(&root)).unwrap();
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
}
