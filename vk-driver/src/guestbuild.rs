//! The host half of `vk-agent build`: [`request`] parses the guest's `vk build` request over
//! the host command channel; its wrapper calls [`serve`]. The context tar on stdin follows
//! [`vk_core::guest_build`], is unpacked under the job's directory, built as a `dockerfile:`
//! image and published in the job's pipeline namespace ([`crate::pipeline::publish_build`]).
//! See `docs/pipeline-images-design.md`.

use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use vk_core::guest_build::{CONTEXT, DOCKERFILE};

use crate::config::Config;
use crate::jobctx::JobCtx;
use crate::pipeline::BuildRef;

/// `vk build` as a VM's `vk-agent build` sends it, its context on stdin.
#[derive(clap::Parser, Debug)]
#[command(
    name = "vk",
    bin_name = "vk",
    about = "the `vk build` request a VM's `vk-agent build` sends"
)]
struct BuildCli {
    #[command(subcommand)]
    cmd: BuildCmd,
}

#[derive(clap::Subcommand, Debug)]
enum BuildCmd {
    /// Build an image from the context on stdin and publish it in the job's pipeline
    Build {
        /// The stage to build [default: the last]
        #[arg(long, value_name = "STAGE")]
        target: Option<String>,
        /// A build argument, NAME=VALUE (repeatable)
        #[arg(long = "build-arg", value_name = "NAME=VALUE")]
        build_arg: Vec<String>,
        /// The image's name in the pipeline: one repository name component
        #[arg(long = "as", value_name = "NAME")]
        name: String,
    },
}

/// What a VM's `vk-agent build` asked for ([`request`]).
#[derive(Debug, PartialEq, Eq)]
pub struct BuildRequest {
    /// Its name under `pipeline/build/`.
    pub name: String,
    pub target: Option<String>,
    pub build_args: Vec<(String, String)>,
}

/// [`crate::vm::service_exec`]'s reading of `argv`, `vk build …`: the request, or the exit
/// status with the reason already on stderr.
pub fn request(argv: &[String]) -> Result<BuildRequest, ExitCode> {
    use clap::Parser;
    let refuse = |why: String| {
        eprintln!("vk: {why}");
        ExitCode::from(2)
    };
    let BuildCmd::Build {
        target,
        build_arg,
        name,
    } = match BuildCli::try_parse_from(argv) {
        Ok(p) => p.cmd,
        Err(e) => {
            // Usage or help text, for the guest's stderr; the exit status says the rest.
            let _ = e.print();
            return Err(ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2)));
        }
    };
    if !vk_hub_proto::token::valid_component(&name) {
        return Err(refuse(format!(
            "invalid image name {name:?} for --as: want one repository name component \
             (lowercase letters, digits, `.`, `_`, `-`)"
        )));
    }
    if let Some(stage) = target.as_deref().filter(|s| !stage_ok(s)) {
        return Err(refuse(format!(
            "invalid --target {stage:?}: not a stage name"
        )));
    }
    let mut build_args = Vec::with_capacity(build_arg.len());
    for arg in build_arg {
        match arg.split_once('=') {
            Some((k, v)) if arg_name_ok(k) => build_args.push((k.to_string(), v.to_string())),
            _ => {
                return Err(refuse(format!(
                    "invalid --build-arg {arg:?}: want NAME=VALUE"
                )));
            }
        }
    }
    Ok(BuildRequest {
        name,
        target,
        build_args,
    })
}

/// A Dockerfile stage name: a letter or digit, then letters, digits, `_`, `.` or `-`.
fn stage_ok(s: &str) -> bool {
    let mut b = s.bytes();
    s.len() <= 128
        && b.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// A build argument's name: a letter or `_`, then letters, digits or `_`.
fn arg_name_ok(s: &str) -> bool {
    let mut b = s.bytes();
    s.len() <= 256
        && b.next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Where a job's guest builds unpack their contexts, in its job dir.
const CONTEXTS: &str = "guest-build";

/// The lock one build of a job holds, in its job dir; `c"guest-build.lock"` in [`lock`].
const LOCK: &str = "guest-build.lock";

/// How long a build waits for the job's lock: the previous build's reaper may still be
/// removing its context.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Why [`admit`] turned a build away: a refusal of the request (exit 2), or a failure on the
/// host's side, a config that does not load or a registry that does not answer (exit 1).
#[derive(Debug)]
enum Denied {
    Refused(anyhow::Error),
    Failed(anyhow::Error),
}

/// `vk service-exec <dir> --allow build [--config <file>] -- vk build …`: build `req` for the CI
/// job whose dir is `dir`, from the context on stdin, under the config at `config`, and print
/// the published image's reference, alone, on stdout; what the build says goes to stderr.
/// Exit 2 when refused before the context is read, 1 when the host fails before it, or the
/// build or its publication fails.
///
/// The job's identity and its registry access come from the environment its supervisor ran
/// with, which the wrapper inherits through the channel's serve and the guest cannot add to:
/// the journaled start the hub sent, read as each executor stage reads it.
pub fn serve(dir: &Path, config: Option<&Path>, req: BuildRequest) -> ExitCode {
    let out = match stdout_to_stderr() {
        Ok(out) => out,
        Err(e) => {
            eprintln!("vk: setting the build's output aside: {e}");
            return ExitCode::from(1);
        }
    };
    let (ctx, lock) = match admit(dir, config, &req) {
        Ok(admitted) => admitted,
        Err(Denied::Refused(e)) => {
            eprintln!("vk: {e:#}");
            return ExitCode::from(2);
        }
        Err(Denied::Failed(e)) => {
            eprintln!("vk: {e:#}");
            return ExitCode::from(1);
        }
    };
    let mut reaper = Command::new(crate::spawn::self_exe());
    reaper.arg(REAP_CMD);
    let reaper = Some(Reaper {
        cmd: reaper,
        lock: &lock,
    });
    let input = std::io::stdin().lock();
    let built = build_and_publish(&ctx, &req, input, reaper, |sources, bundle| {
        let (rootfs, _, guard) = crate::vm::build_image_sources(&ctx, sources)?;
        export_bundle(&rootfs, bundle)?;
        drop(guard);
        Ok(())
    });
    match built {
        Ok(image) => match writeln!(&out, "{image}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vk: writing the image's reference: {e}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("vk: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Point stdout at stderr, for the build's own output, and return the stdout it had.
fn stdout_to_stderr() -> std::io::Result<std::fs::File> {
    std::io::stdout().flush()?;
    // SAFETY: plain descriptor syscalls; the duplicate is a fresh descriptor this call owns.
    let saved = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) };
    if saved < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `saved` is a fresh descriptor nothing else holds.
    let saved = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(saved) });
    // SAFETY: as above.
    if unsafe { libc::dup2(2, 1) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(saved)
}

/// The job in `dir` with the config at `config`, tied to the job's life, and the job's build
/// lock, once every refusal that needs no context is past.
fn admit(
    dir: &Path,
    config: Option<&Path>,
    req: &BuildRequest,
) -> Result<(JobCtx, std::fs::File), Denied> {
    let cfg = Config::load(config).map_err(Denied::Failed)?;
    let ctx = JobCtx::new(cfg).map_err(Denied::Failed)?;
    offered(&ctx, dir).map_err(Denied::Refused)?;
    tie_to_job(&ctx)?;
    // Before the publication check: a build waiting on the lock may be the one publishing the
    // name.
    let job = vk_fs::open_dir_nofollow(&ctx.job_dir).map_err(Denied::Failed)?;
    let lock = lock(job.as_fd(), LOCK_WAIT)?;
    match crate::pipeline::check_publishable(
        &ctx.cfg,
        ctx.job_registry.as_ref(),
        &ctx.job_id,
        &req.name,
    ) {
        Ok(Ok(())) => {}
        Ok(Err(why)) => return Err(Denied::Refused(why)),
        Err(e) => return Err(Denied::Failed(e)),
    }
    Ok((ctx, lock))
}

/// Refuse a build asked for a dir other than `ctx`'s job dir, or on a node that does not
/// offer it.
fn offered(ctx: &JobCtx, dir: &Path) -> Result<()> {
    if !same_dir(dir, &ctx.job_dir) {
        bail!(
            "the build was asked for {}, not this job's dir {}",
            dir.display(),
            ctx.job_dir.display()
        );
    }
    if !ctx.cfg.guest_build() {
        bail!("this node does not offer `vk-agent build` ([executor] guest_build)");
    }
    Ok(())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let id = |p: &Path| {
        std::fs::symlink_metadata(p)
            .ok()
            .map(|m| (m.dev(), m.ino()))
    };
    id(a).is_some_and(|a| Some(a) == id(b))
}

/// How often [`tie_to_job`]'s watchdog checks that the serve is still this process's parent.
const WATCH_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

/// Die with the job: killed once the channel's serve is gone, which dies with the job's
/// supervisor. The serve runs a request in a process group of its own, which a teardown
/// reaching the supervisor's group would miss. Refused when the serve is already gone, or is
/// not the supervisor's.
///
/// A watchdog thread rather than `PR_SET_PDEATHSIG`: the kernel ties that signal to the
/// serve's thread that forked this process, not to the serve, and a runtime retiring that
/// thread would kill the build mid-way (see `spawn.rs`).
fn tie_to_job(ctx: &JobCtx) -> Result<(), Denied> {
    // SAFETY: getppid(2) cannot fail.
    let serve = unsafe { libc::getppid() };
    let supervisor = crate::vm::live_supervisor_pid(ctx);
    if supervisor.is_none() || crate::usage::parent_of(serve) != supervisor {
        return Err(Denied::Refused(anyhow::anyhow!(
            "the job is ending: its supervisor no longer serves this request"
        )));
    }
    watch_parent(serve, WATCH_PERIOD, || {
        // SAFETY: kill(2) of this process.
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    })
    .context("tying the build to its job")
    .map_err(Denied::Failed)
}

/// Run `gone` from a thread of its own once this process's parent is no longer `parent`,
/// checking every `period`; a parent that exits reparents this process. Taken before the
/// check, `parent` catches a parent gone in between.
fn watch_parent(
    parent: libc::pid_t,
    period: std::time::Duration,
    gone: impl FnOnce() + Send + 'static,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("job-watch".into())
        .spawn(move || {
            // SAFETY: getppid(2) cannot fail.
            while unsafe { libc::getppid() } == parent {
                std::thread::sleep(period);
            }
            gone();
        })
        .map(drop)
}

/// Take the job's build lock in the job dir `job`, waiting at most `wait` for it: one build at
/// a time, and the previous one's reaper done.
fn lock(job: BorrowedFd<'_>, wait: std::time::Duration) -> Result<std::fs::File, Denied> {
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    let fd = unsafe {
        libc::openat(
            job.as_raw_fd(),
            c"guest-build.lock".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(Denied::Failed(
            anyhow::Error::new(e).context(format!("opening {LOCK}")),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let deadline = std::time::Instant::now() + wait;
    loop {
        // SAFETY: flock(2) on a descriptor this function holds open.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock {
            return Err(Denied::Failed(
                anyhow::Error::new(e).context(format!("locking {LOCK}")),
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(Denied::Refused(anyhow::anyhow!(
                "another `vk-agent build` of this job is running, or its context is still being \
                 removed: a job runs one at a time"
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Unpack the context on `input` into a fresh directory of the job's, build it with `build`,
/// which fills the bundle directory it is given, and publish that bundle. The directory goes
/// when this returns, whatever the outcome, and with `reaper` when this process is killed
/// first ([`spawn_reaper`]); a build whose reaper could not finish is reclaimed by the next
/// one, under the lock its caller holds, or with the job dir.
fn build_and_publish(
    ctx: &JobCtx,
    req: &BuildRequest,
    input: impl Read,
    reaper: Option<Reaper<'_>>,
    build: impl FnOnce(crate::vm::ImageSources, &Path) -> Result<()>,
) -> Result<BuildRef> {
    let job = vk_fs::open_dir_nofollow(&ctx.job_dir)?;
    let contexts = match vk_fs::create_dir_in(job.as_fd(), OsStr::new(CONTEXTS), 0o700) {
        Ok(fd) => fd,
        Err(e) if already_exists(&e) => vk_fs::open_dir_in(job.as_fd(), OsStr::new(CONTEXTS))?,
        Err(e) => return Err(e),
    };
    // What a killed build left: no other build of the job runs.
    for name in vk_fs::dir_names(contexts.as_fd())? {
        if let Err(e) = remove_in(contexts.as_fd(), &name) {
            eprintln!("vk: warning: removing a leftover build context: {e:#}");
        }
    }
    let name = OsString::from(std::process::id().to_string());
    // Before the directory exists, and dropped after it is removed here: the reaper only ever
    // removes what this process could not.
    let _reaping = reaper
        .map(|r| spawn_reaper(r, contexts.as_fd(), &name))
        .transpose()?;
    let root = Removed {
        parent: contexts.as_fd(),
        name: &name,
        fd: vk_fs::create_dir_in(contexts.as_fd(), &name, 0o700)?,
    };
    // The build reads its sources by path. Below the host-private job dir, where this process
    // made each component, the path names what the descriptors do.
    let root_path = ctx.job_dir.join(CONTEXTS).join(&name);
    let caps = Caps {
        bytes: ctx.cfg.executor.guest_build_max_context.0,
        entries: ctx.cfg.executor.guest_build_max_entries.get(),
    };
    unpack(input, root.fd.as_fd(), caps)?;
    let sources = crate::vm::ImageSources {
        dockerfile: root_path.join(DOCKERFILE),
        context: root_path.join(CONTEXT),
        build_contexts: Vec::new(),
        build_args: req.build_args.clone(),
        stage: req.target.clone(),
        label: format!("{}{}", crate::pipeline::BUILD_REF, req.name),
        service: None,
    };
    vk_fs::create_dir_in(root.fd.as_fd(), OsStr::new(BUNDLE), 0o700)?;
    let bundle = root_path.join(BUNDLE);
    build(sources, &bundle)?;
    crate::pipeline::publish_build(
        &ctx.cfg,
        ctx.job_registry.as_ref(),
        &ctx.job_id,
        &req.name,
        &bundle,
    )
}

/// The hidden `vk` command a reaper runs ([`reap`]).
pub const REAP_CMD: &str = "guest-build-reap";

/// The descriptor a reaper holds the job's build lock on.
const REAPER_LOCK_FD: libc::c_int = 3;

/// The descriptor a reaper finds the job's contexts directory on.
const REAPER_CONTEXTS_FD: libc::c_int = 4;

/// How [`build_and_publish`] starts its reaper: `cmd`, given the context's name, and the job's
/// build lock it holds until it is done.
struct Reaper<'a> {
    cmd: Command,
    lock: &'a std::fs::File,
}

/// Start the reaper of the context `name` in `contexts`: a process that removes it once this
/// one is gone, however it went, and holds the job's build lock until then, so the next build
/// starts on a clean directory. Returns the pipe end whose closing, by this process's exit,
/// is the reaper's signal.
///
/// The channel's serve SIGKILLs a request's process group when the guest disconnects, and the
/// job's teardown gets this process SIGKILLed by its watchdog ([`tie_to_job`]); neither
/// leaves room for a `Drop`. The reaper runs in a session of its own, so the group kill misses
/// it. It has no watchdog: it ends when this process does, after one tree removal, and this
/// process ends with the job, so the reaper outlives the job by that removal at most, racing
/// the teardown's own removal of the job dir harmlessly. Its stdio is not the serve's, which
/// would otherwise wait on it.
fn spawn_reaper(
    reaper: Reaper<'_>,
    contexts: BorrowedFd<'_>,
    name: &OsStr,
) -> Result<std::io::PipeWriter> {
    use std::os::unix::process::CommandExt;
    let Reaper { mut cmd, lock } = reaper;
    let (read, write) = std::io::pipe().context("creating the reaper's pipe")?;
    let lock = lock.as_raw_fd();
    let contexts = contexts.as_raw_fd();
    cmd.arg(name)
        .stdin(read)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid(2), fcntl(2) and dup2(2) are async-signal-safe, as a pre-exec hook needs.
    unsafe {
        cmd.pre_exec(move || {
            // Each descriptor through a copy above both targets first, so neither dup2 lands
            // on the other's source; dup2 clears the copies' close-on-exec on the targets.
            let high = |fd| libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10);
            let (lock, contexts) = (high(lock), high(contexts));
            if lock < 0
                || contexts < 0
                || libc::dup2(lock, REAPER_LOCK_FD) < 0
                || libc::dup2(contexts, REAPER_CONTEXTS_FD) < 0
                || libc::setsid() < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Never waited for: it exits only after this process, which leaves it to be reparented.
    cmd.spawn().context("starting the build context's reaper")?;
    Ok(write)
}

/// `vk guest-build-reap <name>`: once stdin closes, remove the context `name` in the job's
/// contexts directory, on descriptor 4, if it is still there. The job's build lock, on
/// descriptor 3, is released at exit.
pub fn reap(name: &OsStr) -> ExitCode {
    // SAFETY: fcntl(2) on a descriptor number, owning nothing.
    if unsafe { libc::fcntl(REAPER_CONTEXTS_FD, libc::F_GETFD) } < 0 {
        eprintln!(
            "vk: no contexts directory on descriptor {REAPER_CONTEXTS_FD}: {}",
            std::io::Error::last_os_error()
        );
        return ExitCode::from(1);
    }
    // SAFETY: an open descriptor the build passed this process, owned by nothing else here.
    let contexts = unsafe { OwnedFd::from_raw_fd(REAPER_CONTEXTS_FD) };
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 64];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let gone = |e: &anyhow::Error| {
        e.root_cause()
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    };
    let removed = match vk_fs::open_dir_in(contexts.as_fd(), name) {
        Ok(_) => remove_in(contexts.as_fd(), name),
        Err(e) if gone(&e) => Ok(()),
        Err(e) => Err(e),
    };
    match removed {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if gone(&e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vk: removing a build context: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// The bundle a build publishes, beside the context it was built from.
const BUNDLE: &str = "bundle";

/// Make the bundle `vk build --tag` would publish of the build tier's `rootfs`, in `bundle`:
/// its ext4 flattened raw, its runtime config beside it, and its boot kind.
fn export_bundle(rootfs: &Path, bundle: &Path) -> Result<()> {
    let ext4 = bundle.join("runner.ext4");
    crate::qcow2::flatten_to_raw(rootfs, &ext4)
        .with_context(|| format!("exporting {}", rootfs.display()))?;
    let sidecar = crate::build::config_sidecar(rootfs);
    std::fs::copy(&sidecar, crate::build::config_sidecar(&ext4))
        .with_context(|| format!("copying {}", sidecar.display()))?;
    std::fs::write(bundle.join("boot.kind"), "generic-disk").context("writing boot.kind")
}

fn already_exists(e: &anyhow::Error) -> bool {
    e.root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
}

/// Remove the tree `name` in `parent`, followed by no link.
fn remove_in(parent: BorrowedFd<'_>, name: &OsStr) -> Result<()> {
    let dir = vk_fs::open_dir_in(parent, name)?;
    let done = vk_fs::remove_tree_in(parent, name, dir.as_fd())?;
    if !done.skipped.is_empty() {
        bail!(
            "{} kept entries it could not remove",
            PathBuf::from(name).display()
        );
    }
    Ok(())
}

/// A directory removed with what it holds when dropped.
struct Removed<'a> {
    parent: BorrowedFd<'a>,
    name: &'a OsStr,
    fd: OwnedFd,
}

impl Drop for Removed<'_> {
    fn drop(&mut self) {
        match vk_fs::remove_tree_in(self.parent, self.name, self.fd.as_fd()) {
            Ok(done) if !done.skipped.is_empty() => {
                eprintln!("vk: warning: the build context kept entries it could not remove")
            }
            Ok(_) => {}
            Err(e) => eprintln!("vk: warning: removing the build context: {e:#}"),
        }
    }
}

/// How much one context may hold: bytes of the tar stream, headers included, and entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub bytes: u64,
    pub entries: u64,
}

/// `inner`, failing a read that would take more than `left` bytes in all, `over` then set.
struct Capped<'a, R> {
    inner: R,
    left: u64,
    over: &'a Cell<bool>,
}

impl<R: Read> Read for Capped<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        match self.left.checked_sub(n as u64) {
            Some(left) => {
                self.left = left;
                Ok(n)
            }
            None => {
                self.over.set(true);
                Err(std::io::Error::other("the context is over its cap"))
            }
        }
    }
}

/// Unpack the tar `input` into the empty directory `root`, which nothing but this process
/// can reach: the build context under [`CONTEXT`], the Dockerfile as [`DOCKERFILE`].
///
/// Regular files and directories only, no ownership and no setuid, setgid or sticky bit taken
/// from the tar, a file's permission bits kept with its owner's read bit added, a directory's
/// with its owner's three; each path relative, with no empty, `.` or `..` component, under a directory
/// an earlier entry made, and named once. Every component is opened without following a link
/// and every entry created where nothing stood, so with no link in the tree nothing read under
/// `root` leads out of it. `caps` are enforced as the stream is read: crossing either stops
/// it. The tar must name [`DOCKERFILE`], a regular file.
pub fn unpack(input: impl Read, root: BorrowedFd<'_>, caps: Caps) -> Result<()> {
    let context = vk_fs::create_dir_in(root, OsStr::new(CONTEXT), 0o700)?;
    let over = Cell::new(false);
    let mut archive = tar::Archive::new(Capped {
        inner: input,
        left: caps.bytes,
        over: &over,
    });
    let mut unpacker = Unpacker {
        root,
        context: context.as_fd(),
        parent: None,
        dockerfile: false,
    };
    let unpacked = (|| {
        let mut count = 0u64;
        // Raw: the crate would read a GNU long name or a PAX record whole into memory, at any
        // size the guest's header claims, before an entry reached the checks below. Raw, such
        // a record is an entry of its own, refused on its header before its body is read; the
        // agent writes plain ustar, its paths in the header's name and prefix.
        let entries = archive.entries().context("reading the context")?.raw(true);
        for entry in entries {
            let entry = entry.context("reading the context")?;
            count += 1;
            if count > caps.entries {
                bail!(
                    "the context has more than {} entries ([executor] guest_build_max_entries)",
                    caps.entries
                );
            }
            unpacker.entry(entry)?;
        }
        Ok(())
    })();
    if over.get() {
        bail!(
            "the context is over {} bytes ([executor] guest_build_max_context)",
            caps.bytes
        );
    }
    unpacked?;
    if !unpacker.dockerfile {
        bail!("the context names no {DOCKERFILE}");
    }
    Ok(())
}

/// [`unpack`]'s state across entries.
struct Unpacker<'a> {
    root: BorrowedFd<'a>,
    context: BorrowedFd<'a>,
    /// The directory the last entry went into, by its path below [`CONTEXT`].
    parent: Option<(Vec<u8>, OwnedFd)>,
    dockerfile: bool,
}

impl Unpacker<'_> {
    fn entry<R: Read>(&mut self, mut entry: tar::Entry<'_, R>) -> Result<()> {
        let raw = entry.path_bytes().into_owned();
        let shown = raw.escape_ascii().to_string();
        let kind = entry.header().entry_type();
        let dir = match kind {
            tar::EntryType::Regular => false,
            tar::EntryType::Directory => true,
            other => bail!(
                "context entry {shown}: {}, where only regular files and directories are taken",
                kind_name(other)
            ),
        };
        let mode = entry
            .header()
            .mode()
            .with_context(|| format!("context entry {shown}: reading its mode"))?;
        // A directory's name may end in the one `/` tar writers give it.
        let path = match raw.strip_suffix(b"/") {
            Some(p) if dir => p,
            _ => raw.as_slice(),
        };
        let parts: Vec<&[u8]> = path.split(|&b| b == b'/').collect();
        if parts
            .iter()
            .any(|p| p.is_empty() || *p == b"." || *p == b"..")
        {
            bail!(
                "context entry {shown}: not a relative path of named components (no empty, `.` \
                 or `..` one)"
            );
        }
        let (parent, name) = match parts.as_slice() {
            [d] if *d == DOCKERFILE.as_bytes() => {
                if dir {
                    bail!("context entry {shown}: the Dockerfile must be a regular file");
                }
                self.dockerfile = true;
                (self.root, *d)
            }
            [c, below @ ..] if *c == CONTEXT.as_bytes() && !below.is_empty() => {
                let (name, dirs) = below.split_last().context("a name below the context")?;
                (self.parent_of(dirs, &shown)?, *name)
            }
            _ => bail!("context entry {shown}: neither under {CONTEXT}/ nor {DOCKERFILE}"),
        };
        let name = OsStr::from_bytes(name);
        // Each mode set on the open entry, whatever the umask. A directory gets its owner's
        // bits added, which the build needs to read it and its removal to empty it; a file,
        // once written, its owner's read bit, which the build needs.
        let created = if dir {
            vk_fs::create_dir_in(parent, name, 0o700).and_then(|d| {
                use std::os::unix::fs::PermissionsExt;
                std::fs::File::from(vk_fs::reopen_dir(d.as_fd())?)
                    .set_permissions(std::fs::Permissions::from_mode((mode & 0o777) | 0o700))
                    .context("setting its mode")
            })
        } else {
            vk_fs::create_file_in(parent, name, 0o600).and_then(|mut f| {
                use std::os::unix::fs::PermissionsExt;
                std::io::copy(&mut entry, &mut f).context("writing it")?;
                f.set_permissions(std::fs::Permissions::from_mode((mode & 0o777) | 0o400))
                    .context("setting its mode")
            })
        };
        created.map_err(|e| match e.root_cause().downcast_ref::<std::io::Error>() {
            Some(io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::anyhow!("context entry {shown}: named twice")
            }
            _ => e.context(format!("context entry {shown}")),
        })
    }

    /// The directory `dirs` below the context, an earlier entry's, opened component by
    /// component without following a link.
    fn parent_of(&mut self, dirs: &[&[u8]], shown: &str) -> Result<BorrowedFd<'_>> {
        let key = dirs.join(&b'/');
        if self.parent.as_ref().is_none_or(|(k, _)| *k != key) {
            let mut fd: Option<OwnedFd> = None;
            for d in dirs {
                let at = fd.as_ref().map_or(self.context, |f| f.as_fd());
                let next = vk_fs::open_dir_in(at, OsStr::from_bytes(d)).with_context(|| {
                    format!(
                        "context entry {shown}: its directory {} is not one an earlier entry made",
                        d.escape_ascii()
                    )
                })?;
                fd = Some(next);
            }
            self.parent = fd.map(|f| (key, f));
        }
        Ok(self
            .parent
            .as_ref()
            .map_or(self.context, |(_, f)| f.as_fd()))
    }
}

/// What a refused tar entry is, in words.
fn kind_name(kind: tar::EntryType) -> &'static str {
    match kind {
        tar::EntryType::Symlink => "a symlink",
        tar::EntryType::Link => "a hard link",
        tar::EntryType::Char | tar::EntryType::Block => "a device node",
        tar::EntryType::Fifo => "a FIFO",
        tar::EntryType::GNUSparse => "a sparse file",
        tar::EntryType::GNULongName
        | tar::EntryType::GNULongLink
        | tar::EntryType::XHeader
        | tar::EntryType::XGlobalHeader => "a tar extension record",
        _ => "an entry of another type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    const CAPS: Caps = Caps {
        bytes: 1 << 20,
        entries: 100,
    };

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vk-guestbuild-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A tar entry header named `path`, written raw so it may be anything a guest could send.
    fn header(path: &[u8], kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path);
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_size(size);
        h.set_uid(0);
        h.set_gid(0);
        h.set_cksum();
        h
    }

    /// A tar of `entries`: a path, a type, a mode and, for a file, its bytes.
    fn tar_of(entries: &[(&[u8], tar::EntryType, u32, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, kind, mode, data) in entries {
            let h = header(path, *kind, *mode, data.len() as u64);
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    const F: tar::EntryType = tar::EntryType::Regular;
    const D: tar::EntryType = tar::EntryType::Directory;

    fn unpack_into(dir: &Path, tar: &[u8], caps: Caps) -> Result<()> {
        let root = vk_fs::open_dir(dir).unwrap();
        unpack(tar, root.as_fd(), caps)
    }

    fn refusal(tag: &str, tar: &[u8], caps: Caps) -> String {
        let dir = tmpdir(tag);
        let err = unpack_into(&dir, tar, caps).unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        format!("{err:#}")
    }

    /// The context and the Dockerfile land apart, modes kept to the permission bits, a file's
    /// with its owner's read bit and a directory's with its owner's three, nothing setuid.
    #[test]
    fn a_context_unpacks_beside_its_dockerfile() {
        let dir = tmpdir("ok");
        let tar = tar_of(&[
            (b"context/src/", D, 0o755, b""),
            (b"context/src/run.sh", F, 0o4755, b"#!/bin/sh\n"),
            (b"context/secret", F, 0o000, b"s"),
            (b"context/ro", F, 0o444, b"r"),
            (b"context/rx", F, 0o555, b"x"),
            (b"context/sealed/", D, 0o555, b""),
            (b"context/shared/", D, 0o775, b""),
            (b"context/.dockerignore", F, 0o644, b"*.log\n"),
            (b"Dockerfile", F, 0o644, b"FROM scratch\nCOPY . /\n"),
        ]);
        unpack_into(&dir, &tar, CAPS).unwrap();
        let mode = |p: &str| std::fs::metadata(dir.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            std::fs::read(dir.join("Dockerfile")).unwrap(),
            b"FROM scratch\nCOPY . /\n"
        );
        assert_eq!(
            std::fs::read(dir.join("context/src/run.sh")).unwrap(),
            b"#!/bin/sh\n"
        );
        assert_eq!(mode("context/src/run.sh"), 0o755);
        assert_eq!(mode("context/secret"), 0o400);
        assert_eq!(mode("context/ro"), 0o444);
        assert_eq!(mode("context/rx"), 0o555);
        assert_eq!(mode("context/sealed"), 0o755);
        assert_eq!(mode("context/shared"), 0o775);
        assert!(dir.join("context/.dockerignore").is_file());
        assert!(!dir.join("context/Dockerfile").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tar `vk-agent build` writes: ustar headers through the tar crate's own path
    /// handling, a path past 100 bytes split between the header's prefix and name.
    #[test]
    fn a_tar_as_the_agent_writes_it_unpacks() {
        let dir = tmpdir("agent");
        let deep = format!("context/{}/{}", "d".repeat(90), "e".repeat(90));
        let long = format!("{deep}/f");
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |kind, path: &str, data: &[u8]| {
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(kind);
            h.set_mode(0o755);
            h.set_size(data.len() as u64);
            h.set_path(path).unwrap();
            h.set_cksum();
            b.append(&h, data).unwrap();
        };
        add(D, &format!("context/{}", "d".repeat(90)), b"");
        add(D, &deep, b"");
        add(F, &long, b"x");
        add(F, "Dockerfile", b"FROM scratch\n");
        unpack_into(&dir, &b.into_inner().unwrap(), CAPS).unwrap();
        assert_eq!(std::fs::read(dir.join(&long)).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A long name or PAX record is refused on its header, however large it claims to be:
    /// its body, which the stream here never carries, is not read.
    #[test]
    fn tar_extension_records_are_refused_unread() {
        let huge = Caps {
            bytes: u64::MAX,
            entries: 100,
        };
        for kind in [
            tar::EntryType::XHeader,
            tar::EntryType::XGlobalHeader,
            tar::EntryType::GNULongName,
            tar::EntryType::GNULongLink,
        ] {
            let h = header(b"././@LongLink", kind, 0o644, 7 << 30);
            let msg = refusal("ext", h.as_bytes(), huge);
            assert!(msg.contains("a tar extension record"), "{kind:?}: {msg}");
        }
    }

    #[test]
    fn links_devices_and_fifos_are_refused() {
        let df: (&[u8], _, _, &[u8]) = (b"Dockerfile", F, 0o644, b"FROM scratch\n");
        for (kind, what) in [
            (tar::EntryType::Symlink, "a symlink"),
            (tar::EntryType::Link, "a hard link"),
            (tar::EntryType::Char, "a device node"),
            (tar::EntryType::Block, "a device node"),
            (tar::EntryType::Fifo, "a FIFO"),
        ] {
            let tar = tar_of(&[df, (b"context/x", kind, 0o644, b"")]);
            let msg = refusal("kind", &tar, CAPS);
            assert!(msg.contains("context/x") && msg.contains(what), "{msg}");
        }
        // A symlinked Dockerfile too.
        let tar = tar_of(&[(b"Dockerfile", tar::EntryType::Symlink, 0o777, b"")]);
        assert!(refusal("df-link", &tar, CAPS).contains("a symlink"));
    }

    #[test]
    fn paths_out_of_the_tree_are_refused() {
        let df: (&[u8], _, _, &[u8]) = (b"Dockerfile", F, 0o644, b"FROM scratch\n");
        for bad in [
            &b"/etc/passwd"[..],
            b"context/../escape",
            b"context/./x",
            b"context//x",
            b"../x",
            b"context/a/..",
            b"x",
            b"context",
            b"Dockerfile/x",
        ] {
            let tar = tar_of(&[df, (bad, F, 0o644, b"x")]);
            let msg = refusal("path", &tar, CAPS);
            assert!(msg.contains("context entry"), "{bad:?}: {msg}");
        }
        // A directory never made by an earlier entry, or a file where one should be.
        let tar = tar_of(&[df, (b"context/a/b", F, 0o644, b"x")]);
        assert!(refusal("parent", &tar, CAPS).contains("earlier entry"));
        let tar = tar_of(&[
            df,
            (b"context/a", F, 0o644, b"x"),
            (b"context/a/b", F, 0o644, b"x"),
        ]);
        assert!(refusal("file-parent", &tar, CAPS).contains("earlier entry"));
    }

    #[test]
    fn a_name_given_twice_is_refused() {
        let df: (&[u8], _, _, &[u8]) = (b"Dockerfile", F, 0o644, b"FROM scratch\n");
        let tar = tar_of(&[
            df,
            (b"context/a", F, 0o644, b"1"),
            (b"context/a", F, 0o644, b"2"),
        ]);
        assert!(refusal("dup", &tar, CAPS).contains("named twice"));
        let tar = tar_of(&[
            df,
            (b"context/a", D, 0o755, b""),
            (b"context/a/", D, 0o755, b""),
        ]);
        assert!(refusal("dup-dir", &tar, CAPS).contains("named twice"));
        let tar = tar_of(&[df, df]);
        assert!(refusal("dup-df", &tar, CAPS).contains("named twice"));
    }

    #[test]
    fn the_dockerfile_must_be_a_regular_file_and_present() {
        let tar = tar_of(&[(b"context/a", F, 0o644, b"x")]);
        assert!(refusal("no-df", &tar, CAPS).contains("names no Dockerfile"));
        let tar = tar_of(&[(b"Dockerfile/", D, 0o755, b"")]);
        assert!(refusal("df-dir", &tar, CAPS).contains("regular file"));
    }

    #[test]
    fn the_caps_stop_the_transfer() {
        let df: (&[u8], _, _, &[u8]) = (b"Dockerfile", F, 0o644, b"FROM scratch\n");
        let big = vec![7u8; 64 * 1024];
        let tar = tar_of(&[df, (b"context/big", F, 0o644, &big)]);
        let small = Caps {
            bytes: 32 * 1024,
            entries: 100,
        };
        let msg = refusal("bytes", &tar, small);
        assert!(msg.contains("guest_build_max_context"), "{msg}");
        let fits = Caps {
            bytes: tar.len() as u64,
            entries: 2,
        };
        let dir = tmpdir("bytes-fit");
        unpack_into(&dir, &tar, fits).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let names: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("context/f{i}").into_bytes())
            .collect();
        let mut entries = vec![df];
        entries.extend(names.iter().map(|n| (n.as_slice(), F, 0o644, &b"x"[..])));
        let tar = tar_of(&entries);
        let few = Caps {
            bytes: 1 << 20,
            entries: 5,
        };
        let msg = refusal("entries", &tar, few);
        assert!(msg.contains("guest_build_max_entries"), "{msg}");
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// The request names the image, the stage and the build arguments, each checked; it takes
    /// no path and nothing else.
    #[test]
    fn build_requests_parse_strictly() {
        let req = request(&argv(&[
            "vk",
            "build",
            "--target",
            "runner",
            "--build-arg",
            "VERSION=1.2=3",
            "--build-arg",
            "EMPTY=",
            "--as",
            "runner-img",
        ]))
        .unwrap();
        assert_eq!(
            req,
            BuildRequest {
                name: "runner-img".into(),
                target: Some("runner".into()),
                build_args: vec![
                    ("VERSION".into(), "1.2=3".into()),
                    ("EMPTY".into(), String::new())
                ],
            }
        );
        let req = request(&argv(&["vk", "build", "--as", "r"])).unwrap();
        assert_eq!((req.target, req.build_args), (None, vec![]));
        for bad in [
            &["vk", "build"][..],
            &["vk", "build", "--as", "Runner"],
            &["vk", "build", "--as", "a/b"],
            &["vk", "build", "--as", "../x"],
            &["vk", "build", "--as", ""],
            &["vk", "build", "--as", "r", "./ctx"],
            &["vk", "build", "--as", "r", "-f", "Dockerfile"],
            &["vk", "build", "--as", "r", "--build-arg", "NOVALUE"],
            &["vk", "build", "--as", "r", "--build-arg", "=x"],
            &["vk", "build", "--as", "r", "--build-arg", "A-B=x"],
            &["vk", "build", "--as", "r", "--build-arg", "1A=x"],
            &["vk", "build", "--as", "r", "--target", ""],
            &["vk", "build", "--as", "r", "--target", "-x"],
            &["vk", "build", "--as", "r", "--target", "a b"],
            &["vk", "build", "--as", "r", "--config", "/x"],
            &["vk", "exec", "--as", "r"],
        ] {
            assert!(request(&argv(bad)).is_err(), "{bad:?}");
        }
    }

    /// The job dir's lock, at once or not at all.
    fn lock_now(dir: &Path) -> Result<std::fs::File, Denied> {
        lock(
            vk_fs::open_dir(dir).unwrap().as_fd(),
            std::time::Duration::ZERO,
        )
    }

    /// One build of a job at a time: a second is refused while the first holds the lock, and
    /// runs once it is gone.
    #[test]
    fn one_build_at_a_time_per_job() {
        let dir = tmpdir("lock");
        let first = lock_now(&dir).unwrap();
        match lock_now(&dir) {
            Err(Denied::Refused(e)) => assert!(format!("{e:#}").contains("one at a time"), "{e:#}"),
            other => panic!("{other:?}"),
        }
        drop(first);
        lock_now(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A build right behind another waits for its lock, which the previous build's reaper may
    /// hold a little longer, rather than being refused.
    #[test]
    fn a_build_waits_for_the_previous_ones_lock() {
        let dir = tmpdir("lock-wait");
        let first = lock_now(&dir).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(first);
        });
        let job = vk_fs::open_dir(&dir).unwrap();
        lock(job.as_fd(), std::time::Duration::from_secs(20)).unwrap();
        release.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A build asked for another job's dir, or on a node that does not offer it, is refused
    /// before anything else; a request whose serve is not the job supervisor's too.
    #[test]
    fn a_build_is_refused_outside_its_job() {
        let dir = tmpdir("admit");
        let env = [("CUSTOM_ENV_CI_JOB_ID".to_string(), "11".to_string())];
        let ctx = |cfg: Config| JobCtx::for_env(cfg, &env).unwrap();
        let on = ctx(Config {
            state_dir: Some(dir.join("state")),
            ..Default::default()
        });
        std::fs::create_dir_all(&on.job_dir).unwrap();
        offered(&on, &on.job_dir).unwrap();
        let other = dir.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let err = format!("{:#}", offered(&on, &other).unwrap_err());
        assert!(err.contains("not this job's dir"), "{err}");
        let mut off = Config {
            state_dir: Some(dir.join("state")),
            ..Default::default()
        };
        off.executor.guest_build = Some(false);
        let off = ctx(off);
        let err = format!("{:#}", offered(&off, &off.job_dir).unwrap_err());
        assert!(err.contains("guest_build"), "{err}");
        // This test's parent is no job's supervisor.
        match tie_to_job(&on) {
            Err(Denied::Refused(e)) => assert!(format!("{e:#}").contains("job is ending")),
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The watchdog fires once this process's parent is not the one it was given.
    #[test]
    fn the_watchdog_fires_once_the_parent_changes() {
        let (tx, rx) = std::sync::mpsc::channel();
        // SAFETY: getppid(2) cannot fail.
        let parent = unsafe { libc::getppid() };
        let period = std::time::Duration::from_millis(10);
        // Not this process's parent: fires at once.
        watch_parent(parent + 1, period, move || tx.send(()).unwrap()).unwrap();
        rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
        // Its parent: does not.
        let (tx, rx) = std::sync::mpsc::channel();
        watch_parent(parent, period, move || tx.send(()).unwrap()).unwrap();
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
    }

    fn job(prefix: &str) -> vk_hub_proto::dispatch::JobRegistry {
        vk_hub_proto::dispatch::JobRegistry {
            registry_id: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            token: "vkt_x.y".into(),
            expires_at: u64::MAX,
            grants: Vec::new(),
            cache_repo: None,
            pipeline_prefix: Some(prefix.to_string()),
            areas: vec![],
            build_prefix: None,
        }
    }

    /// The context reaches the build as a tree beside its Dockerfile, the bundle the build
    /// makes is published under the job's tag in its pipeline, the reference names it, and
    /// nothing of either stays in the job dir; a second build of the name is refused.
    #[test]
    fn a_guest_context_is_built_published_and_removed() {
        let dir = tmpdir("publish");
        let store = dir.join("store");
        let cfg = Config {
            state_dir: Some(dir.join("state")),
            registry: Some(crate::registry::tests::served_store(&store)),
            ..Default::default()
        };
        let env = [("CUSTOM_ENV_CI_JOB_ID".to_string(), "11".to_string())];
        let mut ctx = JobCtx::for_env(cfg, &env).unwrap();
        ctx.job_registry = Some(job("ci-pipeline/gl/42/7"));
        std::fs::create_dir_all(&ctx.job_dir).unwrap();
        // A context a killed build left behind.
        std::fs::create_dir_all(ctx.job_dir.join("guest-build/1/context")).unwrap();
        let req = request(&argv(&[
            "vk",
            "build",
            "--target",
            "t",
            "--build-arg",
            "A=1",
            "--as",
            "runner",
        ]))
        .unwrap();
        let tar = tar_of(&[
            (b"context/pkg.deb", F, 0o644, b"deb"),
            (b"Dockerfile", F, 0o644, b"FROM scratch\nCOPY pkg.deb /\n"),
        ]);
        let image = build_and_publish(&ctx, &req, tar.as_slice(), None, |sources, bundle| {
            assert_eq!(std::fs::read(sources.context.join("pkg.deb"))?, b"deb");
            assert_eq!(
                std::fs::read(&sources.dockerfile)?,
                b"FROM scratch\nCOPY pkg.deb /\n"
            );
            assert_eq!(sources.stage.as_deref(), Some("t"));
            assert_eq!(sources.build_args, vec![("A".into(), "1".into())]);
            assert_eq!(sources.label, "pipeline/build/runner");
            assert!(!ctx.job_dir.join("guest-build/1").exists());
            std::fs::write(bundle.join("boot.kind"), "generic-disk")?;
            std::fs::write(bundle.join("runner.ext4"), vec![1u8; 4096])?;
            Ok(())
        })
        .unwrap();
        let digest = std::fs::read_to_string(
            store.join("repos/ci-pipeline/gl/42/7/builds/runner/tags/job-11"),
        )
        .unwrap();
        assert_eq!(
            image.to_string(),
            format!("pipeline/build/runner:job-11@{digest}")
        );
        assert_eq!(
            vk_fs::dir_names(
                vk_fs::open_dir(&ctx.job_dir.join("guest-build"))
                    .unwrap()
                    .as_fd()
            )
            .unwrap(),
            Vec::<OsString>::new()
        );
        let err = crate::pipeline::check_publishable(
            &ctx.cfg,
            ctx.job_registry.as_ref(),
            &ctx.job_id,
            "runner",
        )
        .unwrap()
        .unwrap_err();
        assert!(format!("{err:#}").contains("once"), "{err:#}");

        // A context refused, or a build that fails, leaves nothing either.
        let bad = tar_of(&[(b"context/x", tar::EntryType::Symlink, 0o777, b"")]);
        let other = request(&argv(&["vk", "build", "--as", "other"])).unwrap();
        assert!(build_and_publish(&ctx, &other, bad.as_slice(), None, |_, _| Ok(())).is_err());
        let failed = build_and_publish(&ctx, &other, tar.as_slice(), None, |_, _| bail!("no"));
        assert!(failed.is_err());
        assert!(
            vk_fs::dir_names(
                vk_fs::open_dir(&ctx.job_dir.join("guest-build"))
                    .unwrap()
                    .as_fd()
            )
            .unwrap()
            .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Environment keys selecting this test binary's reaper and wrapper roles.
    const AS_REAPER: &str = "VK_TEST_GUEST_BUILD_REAPER";
    const AS_WRAPPER: &str = "VK_TEST_GUEST_BUILD_WRAPPER";

    /// This test binary, running only the test `name`.
    fn this_test(name: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            name,
            "--include-ignored",
            "--quiet",
            "--test-threads=1",
        ]);
        cmd
    }

    /// [`reap`], run by [`a_killed_builds_context_is_reaped`] in a process of its own: its last
    /// argument is the reaper's.
    #[test]
    #[ignore = "a helper process of another test"]
    fn reaper_child() {
        if std::env::var_os(AS_REAPER).is_none() {
            return;
        }
        let args: Vec<OsString> = std::env::args_os().collect();
        let [.., name] = args.as_slice() else {
            panic!("no reaper arguments")
        };
        std::process::exit(if reap(name) == ExitCode::SUCCESS {
            0
        } else {
            1
        });
    }

    /// A build waiting forever on its context, with its reaper, for
    /// [`a_killed_builds_context_is_reaped`] to kill.
    #[test]
    #[ignore = "a helper process of another test"]
    fn wrapper_child() {
        let Some(state) = std::env::var_os(AS_WRAPPER) else {
            return;
        };
        let cfg = Config {
            state_dir: Some(PathBuf::from(state)),
            ..Default::default()
        };
        let env = [("CUSTOM_ENV_CI_JOB_ID".to_string(), "11".to_string())];
        let ctx = JobCtx::for_env(cfg, &env).unwrap();
        let lock = lock_now(&ctx.job_dir).unwrap();
        let mut cmd = this_test("guestbuild::tests::reaper_child");
        cmd.env(AS_REAPER, "1");
        let req = request(&argv(&["vk", "build", "--as", "runner"])).unwrap();
        let reaper = Some(Reaper { cmd, lock: &lock });
        // stdin never ends: the test kills this process while it reads.
        let _ = build_and_publish(&ctx, &req, std::io::stdin(), reaper, |_, _| Ok(()));
    }

    /// A build killed while it reads its context, as the serve kills one whose guest went
    /// away, leaves nothing behind: its reaper removes the context, then lets the next build
    /// take the job's lock.
    #[test]
    fn a_killed_builds_context_is_reaped() {
        use clap::Parser;
        // The command the reaper runs is a hidden `vk` command.
        assert!(crate::Cli::try_parse_from(["vk", REAP_CMD, "1"]).is_ok());
        let dir = tmpdir("reap");
        let job_dir = dir.join("jobs/11");
        std::fs::create_dir_all(&job_dir).unwrap();
        let mut wrapper = this_test("guestbuild::tests::wrapper_child")
            .env(AS_WRAPPER, &dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let context = job_dir.join(CONTEXTS).join(wrapper.id().to_string());
        let until = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while !done() {
                assert!(std::time::Instant::now() < deadline, "{what}");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        until("the build unpacks", &|| context.join(CONTEXT).is_dir());
        wrapper.kill().unwrap();
        wrapper.wait().unwrap();
        until("the reaper removes the context", &|| !context.exists());
        until("the reaper releases the lock", &|| {
            lock_now(&job_dir).is_ok()
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
