//! Ensure a rootless `buildkitd` is reachable, starting one if the socket does not
//! answer, so `virtkit build` needs no externally-managed daemon (and no docker).
//!
//! Rootless buildkitd needs a user namespace in which it can write a uid/gid map
//! and mount overlayfs. On stock Ubuntu with
//! `kernel.apparmor_restrict_unprivileged_userns=1` an *unprofiled* binary may
//! create a userns but the kernel capability-neuters it (uid_map write and mount
//! both EPERM). Two launch paths handle this:
//!   (a) native self-unshare: fork, the child `unshare(CLONE_NEWUSER|CLONE_NEWNS)`,
//!       the parent maps the subuid/subgid range with the setuid helpers
//!       newuidmap/newgidmap, then the child execs buildkitd. Needs an AppArmor
//!       `userns` grant for the binary; podman-free.
//!   (b) podman-unshare fallback: `podman unshare <buildkitd> …`. podman is
//!       AppArmor-profiled for userns, so this works with no extra setup. podman is
//!       used ONLY as a userns launcher — nothing touches containers-storage.
//! (a) is attempted first; on the capability-neuter EPERM it falls back to (b) if
//! podman is on PATH, else returns an error spelling out the one-time AppArmor fix.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Resolved daemon tools + paths for one `ensure` call.
pub(crate) struct Buildkit {
    pub buildctl: PathBuf,
    buildkitd: PathBuf,
    runc: PathBuf,
    root: PathBuf,
    sock: PathBuf,
    config: PathBuf,
}

/// Default GC policy written next to ROOT so the persistent store stays bounded
/// across runs.
const GC_TOML: &str = "\
[worker.oci]
  gc = true
  [[worker.oci.gcpolicy]]
    all = true
    reservedSpace = \"20GB\"
    maxUsedSpace = \"50GB\"
    minFreeSpace = \"10GB\"
";

impl Buildkit {
    /// Resolve tool paths and the persistent ROOT / runtime SOCK locations.
    /// `buildctl`/`buildkitd` override the lookup; otherwise each binary is found
    /// next to the running virtkit binary, then on `$PATH`.
    pub(crate) fn resolve(buildctl: Option<&Path>, buildkitd: Option<&Path>) -> Result<Self> {
        let buildctl = locate("buildctl", buildctl)?;
        let buildkitd = locate("buildkitd", buildkitd)?;
        // buildkit-runc ships in the same dir as buildctl/buildkitd; prefer that
        // (the caller points --build-buildctl/-buildkitd at it) before the generic
        // next-to-virtkit / $PATH lookup, so a caller need only locate the suite once.
        let runc = [buildkitd.parent(), buildctl.parent()]
            .into_iter()
            .flatten()
            .map(|d| d.join("buildkit-runc"))
            .find(|p| p.is_file())
            .map_or_else(|| locate("buildkit-runc", None), Ok)?;

        // The buildkit root is a purely regenerable, GC-bounded build cache, so it
        // belongs under XDG_CACHE_HOME rather than XDG_DATA_HOME (persistent data).
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".cache"));
        let root = cache.join("virtkit-buildkit");
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let sock = runtime.join("virtkit-buildkit.sock");
        let config = cache.join("virtkit-buildkit.gc.toml");

        Ok(Buildkit {
            buildctl,
            buildkitd,
            runc,
            root,
            sock,
            config,
        })
    }

    /// The `unix://…` address buildctl dials.
    pub(crate) fn addr(&self) -> String {
        format!("unix://{}", self.sock.display())
    }

    /// Ensure a daemon is reachable at [`Buildkit::addr`], launching one (path (a)
    /// then (b)) if the socket does not already answer. Returns the addr.
    pub(crate) fn ensure(&self) -> Result<String> {
        let addr = self.addr();
        if self.workers_ok(&addr) {
            return Ok(addr);
        }
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("creating buildkit root {}", self.root.display()))?;
        if let Some(parent) = self.config.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&self.config, GC_TOML)
            .with_context(|| format!("writing {}", self.config.display()))?;
        // a stale socket left by a dead daemon would make bind fail
        let _ = std::fs::remove_file(&self.sock);

        match self.spawn_native() {
            Ok(()) => {}
            Err(e) if is_userns_neutered(&e) && which("podman").is_some() => {
                eprintln!(
                    "virtkit: native userns is capability-neutered ({e:#}); \
                     falling back to `podman unshare`"
                );
                self.spawn_podman()?;
            }
            Err(e) if is_userns_neutered(&e) => bail!(
                "buildkitd userns is capability-neutered and podman is not on PATH.\n\
                 Install a one-time AppArmor profile granting userns to the binary:\n\
                 \n  sudo tee /etc/apparmor.d/virtkit >/dev/null <<'EOF'\n\
                 abi <abi/4.0>,\n\
                 include <tunables/global>\n\
                 profile virtkit {} flags=(unconfined) {{\n\
                 \x20\x20userns,\n\
                 \x20\x20include if exists <local/virtkit>\n\
                 }}\n\
                 EOF\n  sudo apparmor_parser -r /etc/apparmor.d/virtkit\n\
                 \nThen re-run; the native (podman-free) path will work.",
                self.buildkitd.display()
            ),
            Err(e) => return Err(e),
        }
        self.wait_ready(&addr)?;
        Ok(addr)
    }

    /// buildkitd flag vector shared by both launch paths.
    fn flags(&self) -> Vec<String> {
        vec![
            "--config".into(),
            self.config.display().to_string(),
            "--root".into(),
            self.root.display().to_string(),
            "--addr".into(),
            self.addr(),
            "--oci-worker-no-process-sandbox".into(),
            "--oci-worker-snapshotter".into(),
            "overlayfs".into(),
            "--oci-worker-binary".into(),
            self.runc.display().to_string(),
        ]
    }

    /// (a) native self-unshare: fork, child enters a new user+mount namespace,
    /// parent maps the subuid/subgid range via newuidmap/newgidmap, child execs
    /// buildkitd. On this host the setuid newuidmap can write the id map even when
    /// the userns is capability-neutered, so the decisive test is whether the child
    /// can *mount* — the child probes a tmpfs first and reports the outcome, so the
    /// caller falls back to podman before a daemon that cannot build is launched.
    fn spawn_native(&self) -> Result<()> {
        let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
        let (sub_uid, sub_uid_n) = subid("/etc/subuid", uid)?;
        let (sub_gid, sub_gid_n) = subid("/etc/subgid", gid)?;

        let log = self.log_file()?;
        // maps pipe: child blocks until the parent has written its id maps (else
        // buildkitd would run before the maps land and see itself as nobody).
        let maps = Pipe::new()?;
        // status pipe: child reports the mount-probe outcome before exec — a byte
        // STATUS_OK means it is execing buildkitd; anything else (incl. a closed
        // pipe) means the userns is mount-neutered and the caller should fall back.
        let status = Pipe::new()?;

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).context("fork");
        }
        if pid == 0 {
            // ---- child ----
            maps.close_write();
            status.close_read();
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                unsafe { libc::_exit(71) };
            }
            maps.read_byte(); // wait for the parent's id maps
            // the real capability-neuter shows up here: can this userns mount?
            if !probe_can_mount() {
                unsafe { libc::_exit(73) };
            }
            status.write_byte(STATUS_OK);
            let err = self.exec_buildkitd(&log);
            eprint!("virtkit: exec buildkitd failed: {err}");
            unsafe { libc::_exit(72) };
        }
        // ---- parent ----
        maps.close_read();
        status.close_write();
        let map_res = (|| -> Result<()> {
            run_idmap("newuidmap", pid, uid, sub_uid, sub_uid_n)?;
            run_idmap("newgidmap", pid, gid, sub_gid, sub_gid_n)?;
            Ok(())
        })();
        maps.write_byte(0); // release the child so it probes + execs (or reports)

        if let Err(e) = map_res {
            let mut st = 0;
            unsafe { libc::waitpid(pid, &mut st, 0) };
            return Err(e);
        }
        match status.read_byte() {
            // daemon is execing; do NOT wait — it is the long-lived daemon
            Some(STATUS_OK) => Ok(()),
            _ => {
                let mut st = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
                bail!("buildkitd userns cannot mount (EPERM): capability-neutered")
            }
        }
    }

    /// exec buildkitd in the (already unshared) child, redirecting stdio to the log.
    fn exec_buildkitd(&self, log: &std::fs::File) -> std::io::Error {
        Command::new(&self.buildkitd)
            .args(self.flags())
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("dup log"))
            .stderr(log.try_clone().expect("dup log"))
            // own session so it outlives this fork
            .process_group(0)
            .exec()
    }

    /// (b) podman-unshare fallback: `podman unshare <buildkitd> <flags…>`, detached.
    fn spawn_podman(&self) -> Result<()> {
        let log = self.log_file()?;
        let mut cmd = Command::new("podman");
        cmd.arg("unshare").arg(&self.buildkitd).args(self.flags());
        unsafe {
            cmd.pre_exec(|| {
                // detach into its own session so the daemon outlives virtkit
                libc::setsid();
                Ok(())
            });
        }
        cmd.stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("spawning `podman unshare buildkitd`")?;
        Ok(())
    }

    fn log_file(&self) -> Result<std::fs::File> {
        let path = self.root.with_extension("log");
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))
    }

    /// One `buildctl debug workers` probe — true once the daemon answers.
    fn workers_ok(&self, addr: &str) -> bool {
        Command::new(&self.buildctl)
            .args(["--addr", addr, "debug", "workers"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Poll the socket for readiness up to ~15s after launch.
    fn wait_ready(&self, addr: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.workers_ok(addr) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        bail!(
            "buildkitd did not become ready within 15s; see {}",
            self.root.with_extension("log").display()
        );
    }
}

/// Heuristic: did a launch fail because the kernel capability-neutered the userns?
/// Both the uid_map write (via newuidmap) and the mount surface as EPERM.
fn is_userns_neutered(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_lowercase();
    s.contains("permission denied") || s.contains("eperm") || s.contains("operation not permitted")
}

/// Locate a helper binary: explicit override, else next to the running virtkit
/// binary, else on `$PATH`.
fn locate(name: &str, override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let cand = dir.join(name);
        if cand.is_file() {
            return Ok(cand);
        }
    }
    which(name)
        .with_context(|| format!("{name} not found (pass an explicit --{name} or add it to PATH)"))
}

/// First executable named `name` on `$PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Read the current user's subuid/subgid range (`<name-or-uid>:start:count`) for
/// the given id from `/etc/subuid` or `/etc/subgid`.
fn subid(file: &str, id: u32) -> Result<(u32, u32)> {
    let name = username(id);
    let mut s = String::new();
    std::fs::File::open(file)
        .with_context(|| format!("opening {file}"))?
        .read_to_string(&mut s)
        .with_context(|| format!("reading {file}"))?;
    for line in s.lines() {
        let f: Vec<&str> = line.trim().split(':').collect();
        if f.len() != 3 {
            continue;
        }
        let matches = f[0] == id.to_string() || name.as_deref() == Some(f[0]);
        if matches && let (Ok(start), Ok(count)) = (f[1].parse::<u32>(), f[2].parse::<u32>()) {
            return Ok((start, count));
        }
    }
    bail!("no subordinate id range for uid/gid {id} in {file}");
}

/// Resolve a uid to its login name (for matching name-keyed /etc/subuid lines).
fn username(uid: u32) -> Option<String> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    name.to_str().ok().map(str::to_string)
}

/// Map id 0 of the child's userns to the current id, then `count` ids starting at
/// `sub` to ids 1.. — the standard rootless mapping newuidmap/newgidmap enforce
/// against /etc/sub{u,g}id.
fn run_idmap(tool: &str, pid: i32, id: u32, sub: u32, count: u32) -> Result<()> {
    let st = Command::new(tool)
        .args([
            pid.to_string(),
            "0".into(),
            id.to_string(),
            "1".into(),
            "1".into(),
            sub.to_string(),
            count.to_string(),
        ])
        .status()
        .with_context(|| format!("running {tool}"))?;
    if !st.success() {
        // newuidmap exits non-zero (and prints EPERM) when the userns is neutered.
        bail!("{tool} failed ({st}) — likely EPERM (userns capability-neutered)");
    }
    Ok(())
}

/// Child→parent status byte: the native userns can mount, so buildkitd is execing.
const STATUS_OK: u8 = 1;

/// In the (already unshared + id-mapped) child, test whether the userns can mount.
/// A `tmpfs` mount needs the same CAP_SYS_ADMIN the kernel neuters under
/// `apparmor_restrict_unprivileged_userns`, so this distinguishes a working native
/// userns from one where only the setuid id-map helper succeeded. Async-signal
/// territory: raw syscalls only, no allocation.
fn probe_can_mount() -> bool {
    // mount tmpfs over /tmp (always present); undo it on success so the child's
    // subsequent buildkitd sees a clean tree.
    let src = c"none";
    let target = c"/tmp";
    let fstype = c"tmpfs";
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return false;
    }
    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    true
}

/// A unix pipe with explicit per-end ownership, used to synchronize the native
/// fork (id-map handshake + mount-probe status). Kept minimal: the fork child runs
/// in async-signal-unsafe territory, so the byte ops are raw syscalls.
struct Pipe {
    rd: libc::c_int,
    wr: libc::c_int,
}

impl Pipe {
    fn new() -> Result<Self> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("pipe");
        }
        Ok(Pipe {
            rd: fds[0],
            wr: fds[1],
        })
    }
    fn close_read(&self) {
        unsafe { libc::close(self.rd) };
    }
    fn close_write(&self) {
        unsafe { libc::close(self.wr) };
    }
    fn write_byte(&self, b: u8) {
        let buf = [b];
        let _ = unsafe { libc::write(self.wr, buf.as_ptr() as *const libc::c_void, 1) };
    }
    /// Read one byte; `None` on EOF (the writer closed without sending).
    fn read_byte(&self) -> Option<u8> {
        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(self.rd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        (n == 1).then_some(buf[0])
    }
}
