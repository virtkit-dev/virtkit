//! `vk run` — dev: boot a generic OCI image as a microVM directly,
//! no gitlab-runner. The rootfs comes from a `source::Source` (a registry pull or
//! `docker export`, chosen by `--source`); it is turned into a cpio initramfs (RAM) or a
//! native ext4 disk, with the static virtkit-agent injected as PID 1; and booted on
//! an all-built-in kernel (the pinned `vmlinux`) — no modules, and no initrd
//! for the disk path (virtio-blk + ext4 are built in). docker/cloud-hypervisor
//! aside (docker only with `--source docker`/`auto`), nothing else is needed.

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use tokio_util::sync::CancellationToken;
use vk_core::addr::SocketAddr;

use crate::source::Source;
use crate::timing::{Phase, Timings};
use crate::vmm::Vmm;

/// Who runs as PID 1 in the guest. `Default` = vk-agent (virtkit's default); `Image`
/// = the image's own init (`/sbin/init`, e.g. systemd) via the preinit handoff;
/// `Entrypoint` = the image's ENTRYPOINT+CMD via that same handoff, for an image whose
/// entrypoint prepares the machine and only then execs the real init — a step `Image`
/// skips. The entrypoint runs as root, unlike `docker run`'s honoring of `USER`: it is
/// PID 1, and a machine-preparing entrypoint (and any init it execs) needs root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum InitSource {
    /// vk-agent, virtkit's own PID 1
    Default,
    /// the image's own init (`/sbin/init`, e.g. systemd), via the preinit handoff
    Image,
    /// the image's ENTRYPOINT+CMD, via that same handoff
    ///
    /// For an image whose entrypoint prepares the machine and only then execs the real
    /// init — a step `image` skips.
    Entrypoint,
}

impl InitSource {
    /// Which [`ImageInit`] axis the guest hands PID 1 to, or `None` for the agent.
    /// Exhaustive on purpose: a new axis has to say here what PID 1 becomes, rather
    /// than reaching the guest as a token nothing acts on.
    pub fn image_init(self) -> Option<vk_core::runcfg::ImageInit> {
        use vk_core::runcfg::ImageInit;
        match self {
            InitSource::Default => None,
            InitSource::Image => Some(ImageInit::Init),
            InitSource::Entrypoint => Some(ImageInit::Entrypoint),
        }
    }

    /// Does this hand PID 1 to the image? Every guard that rejects a flag the preinit
    /// handoff cannot carry, and the boot-medium choice that selects that handoff, ask
    /// exactly this.
    pub fn is_image(self) -> bool {
        self.image_init().is_some()
    }

    /// The cmdline fragment (leading space, empty for `Default`) telling the guest agent
    /// what PID 1 becomes.
    pub fn handoff_tokens(self) -> String {
        use vk_core::runcfg::ImageInit;
        let Some(axis) = self.image_init() else {
            return String::new();
        };
        let mut tokens = format!(" VIRTKIT_INIT={}", axis.token());
        // The image's own init needs its path spelled out. An entrypoint argv rides the
        // boot config the agent already reads instead, so nothing with spaces in it has
        // to survive the kernel cmdline.
        if axis == ImageInit::Init {
            tokens.push_str(" VIRTKIT_HANDOFF=/sbin/init");
        }
        tokens
    }
}

/// The `--init` / `x-virtkit.init` value this axis is spelled as, for error messages.
impl std::fmt::Display for InitSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.image_init().map_or("default", |axis| axis.token()))
    }
}

/// Which kernel the guest boots on. `Default` = virtkit's pinned/embedded kernel
/// (virtio + ext4 built in); `Image` = the image's own `/boot/vmlinuz` + its modules,
/// extracted host-side; `Path` = an explicit vmlinux/bzImage file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelSource {
    Default,
    Image,
    Path(PathBuf),
}

impl KernelSource {
    /// clap `value_parser`: the literal `default`/`image` map to those variants,
    /// anything else is a path to a kernel file.
    pub fn parse(s: &str) -> std::result::Result<Self, std::convert::Infallible> {
        Ok(match s {
            "default" => KernelSource::Default,
            "image" => KernelSource::Image,
            other => KernelSource::Path(PathBuf::from(other)),
        })
    }
}

const VSOCK_PORT: u32 = 4444;
/// vsock port the guest SSH-agent forwarder dials; the host splices it to `$SSH_AUTH_SOCK`.
pub(crate) const SSH_AGENT_VSOCK_PORT: u32 = 2223;
/// Guest vsock port the agent's ssh-serve listens on (`--ssh`); mirrors the
/// agent's `SSH_VSOCK_PORT`.
const SSH_VSOCK_PORT: u32 = 2222;
/// vsock port the guest's tap bridge dials to reach the userspace switch.
const NET_VSOCK_PORT: u32 = 1024;
/// vsock port the guest's host-exec forwarder dials (`--host-exec`); the host side
/// is a `vk-agent serve` on the bridged per-port socket, so guest tooling can run
/// host commands through its allowlist wrapper. Sits next to the control port (1099).
const HOST_EXEC_PORT: u32 = 1100;
/// The run LAN: gateway .1, the run VM .2, services from the top down.
const RUN_SUBNET: &str = "192.168.127.0/24";

/// How the host re-invokes the agent's native subcommands (`fsfreeze`, `mount`, `copy`,
/// `fsmark`) inside the guest. `/proc/self/exe` resolves, in the forked child, to the
/// running agent binary — so this works whether the agent was injected into the rootfs
/// (legacy) or booted from an initramfs and pivoted in (its on-disk path then gone).
pub(crate) const GUEST_AGENT: &str = "/proc/self/exe";

/// Guest mountpoint of a `--workdir` host-dir share (the live tree the command runs in).
const WORKDIR_MOUNT: &str = "/work";

/// Where the switches of a run or build publish the bytes they forwarded, in the same work
/// dir, for the resource line each phase ends with. Every switch of a build appends its own
/// deltas, so the file is the whole phase's traffic.
pub(crate) const NET_BYTES: &str = "net.bytes";

/// How long a run waits for its switch to publish and exit at teardown. Long enough for a
/// signal and one append, short enough that a wedged switch costs the run nothing anyone
/// would notice.
const SWITCH_STOP: Duration = Duration::from_millis(300);

/// Audit-mode channel filename in a switch's work dir (or the build scratch): the switch
/// appends every external domain the guest resolves, the caller prints the summary at the
/// end (see egress_report). Same basename the gitlab executor uses in the job dir.
pub(crate) const AUDIT_LOG: &str = "egress-audit.log";

/// Where a `run <image>` rootfs comes from.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
pub enum SourceMode {
    /// pull straight from a registry (no docker daemon)
    Oci,
    /// export from the local docker daemon (`docker export`)
    Docker,
    /// resolve over the registry, falling back to docker for an unpushed image
    ///
    /// Only a registry not-found falls back; auth and network errors surface instead.
    Auto,
}

pub struct RunArgs {
    /// Image to boot (a docker ref or an OCI reference). Ignored when `dockerfile` is set
    /// — the rootfs is then built from the Dockerfile target.
    pub image: String,
    /// Boot a Dockerfile target instead of an image: build (or cache-restore, with
    /// `cache_registry`) the target into an ext4 and boot it — no explicit `--out`
    /// ext4. Several files merge into one stage namespace; empty = an image boot.
    pub dockerfiles: Vec<PathBuf>,
    /// Target stage to boot (AS name or index; default: the last stage), with `dockerfiles`.
    pub target: Option<String>,
    /// Build-context roots, zipped positionally with `dockerfiles` (default: each
    /// Dockerfile's own directory).
    pub contexts: Vec<PathBuf>,
    /// Named build contexts (`--build-context <name>=<dir>`): extra directories a
    /// `COPY --from=<name>` may read, outside the Dockerfile's own context.
    pub build_contexts: Vec<(String, PathBuf)>,
    /// Instruction cache for a Dockerfile boot: each stage's ext4 is pushed/pulled by
    /// its content key, so a repeat boot restores instead of rebuilding. A registry
    /// repo, an absolute store directory path, or `none` to disable; `None` = the
    /// builtin local store (`vk_registry::default_root`).
    pub cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback vk-registry).
    pub cache_insecure: bool,
    /// `--build-arg NAME=VALUE` overrides for the Dockerfile build.
    pub build_args: Vec<(String, String)>,
    /// host dir shared read-write into the guest (at WORKDIR_MOUNT); the command runs
    /// there, so its outputs land back on the host. `None` = no share.
    pub workdir: Option<PathBuf>,
    /// Which kernel the guest boots on: virtkit's pinned kernel (`Default`), the
    /// image's own kernel + modules (`Image`), or an explicit kernel file (`Path`).
    pub kernel: KernelSource,
    /// Keep `console=ttyS0` (don't rewrite to hvc0) for a BYO stock kernel whose
    /// virtio-console is modular (`vk run --console-serial`). See [`crate::vmm::VmSpec`].
    pub console_serial: bool,
    /// Expose the guest PMU to the primary VM (`vk run --pmu`, trusted guests
    /// only). See [`crate::vmm::VmSpec::pmu`].
    pub pmu: bool,
    /// Let the primary VM run microVMs of its own (`vk run --nested`), on top of any
    /// `x-virtkit.nested` a `--primary` service declares. Compose services choose per
    /// service through that marker; build stages never nest. There is no off-switch: a
    /// `--primary` service that declares nesting gets it whether or not the flag is
    /// passed. See [`effective_nested`] and [`crate::vmm::VmSpec::nested`].
    pub nested: bool,
    /// `None` uses the vk-agent embedded in `vk` (or the on-disk default).
    pub agent: Option<PathBuf>,
    pub cloud_hypervisor: PathBuf,
    /// where the rootfs comes from for an image boot (registry pull / docker export / auto)
    pub source: SourceMode,
    pub ca: Option<PathBuf>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub insecure: bool,
    /// Primary VM sizing (`--cpus`/`--mem`). `None` = a `--primary` service's own
    /// `x-virtkit.cpus`/`.mem`, else [`crate::units::DEFAULT_CPUS`]/[`crate::units::DEFAULT_MEM`] —
    /// an explicit flag overrides the service's declaration, like `--init`/`--kernel`.
    pub cpus: Option<u32>,
    pub mem: Option<String>,
    /// Per-service sizing overrides (`--service-cpus`/`--service-mem NAME=VALUE`),
    /// layered over each named compose service's `x-virtkit` declaration.
    pub service_cpus: Vec<(String, u32)>,
    pub service_mem: Vec<(String, String)>,
    pub boot_timeout_secs: u64,
    /// `--vm-name` template for the VMM process name, `{name}` expanding to the stage /
    /// image / service name (see [`crate::vmm::resolve_proc_name`]). Default `vk:{name}`.
    pub vm_name: String,
    /// boot the rootfs as a cpio initramfs held in RAM instead of the default
    /// native-ext4 disk (needs --mem of roughly three times the image size)
    pub ram: bool,
    /// Who runs as PID 1 in the guest: vk-agent (`Default`), the image's own
    /// init/systemd (`Image`), or the image's ENTRYPOINT+CMD (`Entrypoint`) — the
    /// latter two via the preinit handoff, and both requiring an ext4 (a `-f` build
    /// or a non-`--ram` image).
    pub init: InitSource,
    /// attach an interactive shell once the guest is up (needs a terminal)
    pub shell: bool,
    /// allocate a pty for the command and wire it to the local terminal, so it runs
    /// interactively (`docker run -t`; needs a terminal). Ignored under `--shell`.
    pub tty: bool,
    /// give the guest egress via a userspace `vk switch` (DHCP + DNS + proxy);
    /// forced on by `compose` (the services live on that switch's LAN)
    pub net: bool,
    /// `--audit-egress`: record every external domain the *booted guest* resolves and print
    /// a "domains contacted" summary (with per-domain counts) when the run ends. Requires
    /// `net` (the switch is the resolver); observes without restricting egress.
    pub audit_egress: bool,
    /// `--build-audit-egress`: audit the `-f`/`--compose` *build*'s `RUN` egress instead of
    /// (or as well as) the booted guest — the build-phase counterpart of `audit_egress`,
    /// mirroring `--net` vs `--build-net`. Unused for a plain image boot (no build).
    pub build_audit_egress: bool,
    /// opt-in credential-injecting registry proxy: the upstream registry base URL
    /// (`scheme://host`). `vk` runs a host-local proxy forwarding to it with the
    /// `--username`/`--password`/`--ca` credentials, and the guest reaches it
    /// credential-free at `registry.vk` (needs `--net`). `None` = disabled.
    pub registry_proxy: Option<String>,
    /// compose file whose services boot as sibling unit VMs on the run switch,
    /// resolvable by alias, torn down with the run. Images materialize per run
    /// into the work dir; the instruction cache provides repeat-run warmth.
    pub compose: Option<PathBuf>,
    /// activated compose profiles (profiled services stay down unless activated
    /// or depended on)
    pub profiles: Vec<String>,
    /// boot this compose service as the PRIMARY run VM (`docker compose run`):
    /// its image is the rootfs, its merged config the command's env (and, with no
    /// trailing command, its entrypoint+cmd the command); only its depends_on
    /// closure boots as siblings. Requires `compose`; excludes image/`-f`.
    pub primary: Option<String>,
    /// Egress for the `--file` build's `RUN` guests (`--build-net`,
    /// `--build-allow-ip`, `--build-allow-name`). Unused for an image boot.
    pub build_net: crate::build::BuildNet,
    /// forward the host SSH agent into the guest (keys never enter the guest)
    pub ssh_agent: bool,
    /// expose only these ~/.ssh/config host aliases (filtered agent + injected config);
    /// implies SSH-agent forwarding
    pub ssh_hosts: Vec<String>,
    /// serve SSH into the guest (the agent's ssh-serve over vsock; no sshd in the
    /// image) and print the ready-to-paste ssh command; sessions run as `ssh_user`
    pub ssh: bool,
    /// public keys authorised for `ssh` (OpenSSH format); empty = the standard
    /// ~/.ssh/id_*.pub identities
    pub ssh_keys: Vec<String>,
    /// user `ssh` sessions log in as (root unless the image has better — a dev
    /// image's unprivileged user keeps shared-tree ownership coherent)
    pub ssh_user: String,
    /// pin the run's scratch dir (sockets, console log) to a stable path instead
    /// of a fresh temp dir, so external tooling can attach to the running VM; the
    /// directory is reused across runs and never removed
    pub state_dir: Option<PathBuf>,
    /// extra host-dir bind mounts into the primary (beyond `workdir`), same
    /// semantics as a `--primary` primary's compose volumes
    pub volumes: Vec<crate::compose::Volume>,
    /// in-guest symlinks (`src:dest`) created after the mounts — the single-file
    /// share escape hatch (virtiofs shares directories only); dangling sources
    /// are skipped by the agent
    pub symlinks: Vec<(String, String)>,
    /// raw host disk images attached after any rootfs disk (so vdb, vdc, … — but vda
    /// first under `--ram`, which has no rootfs disk) with the read-only flag — `vk run
    /// --disk`. The guest reads/writes them directly, so it can partition and install
    /// into a disk image (see the runner host-image build).
    pub extra_disks: Vec<(PathBuf, bool)>,
    /// record what the guest does from boot, one sample of its /proc every this many
    /// seconds (`vk run --atop[=SECS]`) — the same recording a CI job's guest makes,
    /// landing in `<state dir>/atop/atop.log` for `vk atop` to read. `None` = off.
    pub atop: Option<u64>,
    /// extra environment for the guest (`--env`/`--env-file`, flags last so they
    /// win), appended to the image env and persisted in-guest for login shells
    pub env: Vec<(String, String)>,
    /// serve host commands to the guest: a host-side `vk-agent serve` on a bridged
    /// vsock port, surfaced in-guest at /run/vk/host.sock
    pub host_exec: bool,
    /// force every host-exec command through this program (`serve --exec-wrapper`),
    /// e.g. an allowlist dispatcher
    pub host_exec_wrapper: Option<PathBuf>,
    /// client env vars passed through to the wrapper (`serve --exec-wrapper-env` globs)
    pub host_exec_env: Vec<String>,
    /// a `-f`/`--primary`/compose build may restore stages from the instruction
    /// cache but must not execute anything; a cache miss aborts (exit 3 at the CLI)
    pub require_cached: bool,
    /// daemonize once the guest is ready (foreground build/boot, background after); see
    /// [`crate::detach`]. Set only via the CLI `--detach` fork path.
    pub detach: bool,
    /// After the detached run's startup command, keep the VM alive until its exec server
    /// has had no active command for this many seconds. `Some(0)` waits until an explicit
    /// stop instead. The guest enforces the non-zero timeout and powers itself off.
    pub inactivity_timeout_secs: Option<u64>,
    /// where a `--detach` run redirects its output after detaching (default: discard)
    pub detach_log: Option<PathBuf>,
    pub command: Vec<String>,
}

pub async fn run(args: &RunArgs, cfg: &crate::config::Config) -> Result<()> {
    // SAFETY: isatty has no failure mode beyond returning 0
    if (args.shell || args.tty) && unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        let flag = if args.shell { "--shell" } else { "-t" };
        bail!("{flag} requires stdin and stdout to be a terminal");
    }
    // The VMM process-name template for every VM this run boots (the primary, plus any
    // compose siblings and Dockerfile stage builds, which reach it via the process-global).
    crate::vmm::set_vm_name_template(args.vm_name.clone());
    let work = match &args.state_dir {
        Some(dir) => WorkDir::pinned(dir.clone())?,
        None => {
            WorkDir::create(default_scratch_base()?.join(format!("launch-{}", std::process::id())))?
        }
    };
    // The byte channel is a sum over everything appended to it, and a work dir can outlive the
    // run that made it: `--state-dir` is created-or-reused and never removed, and a run killed
    // by a signal leaves its `launch-<pid>` behind for a recycled pid to find. Cleared here so
    // this run reports its own traffic rather than every earlier run's on top of it.
    let _ = std::fs::remove_file(work.path.join(NET_BYTES));
    // Resolve the agent and kernel: an explicit flag wins, else the copy embedded
    // in `vk` (served from a memfd), else the on-disk default.
    // Held for the VM's lifetime: an embedded asset lives in a memfd whose
    // /proc/self/fd path is only valid while the fd is open.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, args.agent.as_deref())?;
    if !agent.is_embedded() && !agent.path.is_file() {
        bail!(
            "vk-agent not found at {} (pass --agent, or use a `vk` with it embedded)",
            agent.path.display()
        );
    }
    // Resolve the pinned/explicit kernel: `--kernel <path>` wins, else the embedded
    // pinned kernel. With `--kernel image` the boot kernel is extracted from the image
    // instead, so a pinned kernel need not exist — skip its is-file check.
    let kernel_path = match &args.kernel {
        KernelSource::Path(p) => Some(p.as_path()),
        KernelSource::Default | KernelSource::Image => None,
    };
    let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, kernel_path)?;
    if args.kernel != KernelSource::Image && !kernel.is_embedded() && !kernel.path.is_file() {
        bail!(
            "kernel not found at {} (pass --kernel, or use a `vk` with it embedded)",
            kernel.path.display()
        );
    }
    // The host config (loaded once in cli_main) drives image resolution (registry/docker
    // proxy, local dir) and the shared image cache location. `vk run` is rootless and
    // usually has no config file, so defaults apply; its cache then lives under
    // $XDG_DATA_HOME rather than the CI default /var/lib/virtkit (unwritable for a dev),
    // unless the config pins a state_dir.
    let state_dir = match &cfg.state_dir {
        Some(dir) => dir.clone(),
        None => default_data_base()?,
    };

    // No primary (no image, no -f, no --primary) + a compose file = compose up:
    // services only, held until ctrl-c.
    if args.image.is_empty() && args.dockerfiles.is_empty() && args.primary.is_none() {
        if args.atop.is_some() {
            bail!("--atop records the primary VM, and a services-only compose run boots none");
        }
        return compose_up(args, cfg, &state_dir, &work.path, &agent.path, &kernel.path).await;
    }
    build_and_boot(args, cfg, &state_dir, &work.path, &agent.path, &kernel.path).await
}

/// Default base for `vk run`'s durable shared image cache: `$XDG_DATA_HOME/virtkit`, else
/// `~/.local/share/virtkit`. Distinct from `default_scratch_base` (the transient launch
/// scratch under `$XDG_CACHE_HOME`): the materialized image bases and built stages here
/// persist across runs (bounded by idle eviction), so they belong in the data dir — the
/// same home the instruction store (`vk_registry::default_root`) uses.
pub(crate) fn default_data_base() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("virtkit"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_DATA_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/share/virtkit"))
}

/// Default base for a run's launch scratch: `$XDG_CACHE_HOME/virtkit`, else
/// `~/.cache/virtkit`. Deliberately NOT `std::env::temp_dir()`: that is often a small
/// RAM-backed tmpfs (e.g. a 16 GiB `/tmp`), and a `-f` build writes its stage ext4s and the
/// assembled `root.ext4` here — a large build would exhaust the tmpfs (ENOSPC) while the
/// real disk sits idle. Cache semantics fit (transient, regenerable, removed on drop); the
/// durable instruction store lives under `$XDG_DATA_HOME` instead. `--state-dir` overrides
/// this with a caller-chosen path. The short `launch-<pid>` leaf keeps the AF_UNIX socket
/// paths created under here well within the 108-byte limit. Shared with the build path
/// (`build_units`), which anchors a cache-only build's scratch here for the same reason.
pub(crate) fn default_scratch_base() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("virtkit"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_CACHE_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".cache/virtkit"))
}

/// A launch's named scratch dir — sockets, logs, and a `-f` build's ext4 live here
/// (an image boot's media are unlinked scratch fds). Removed on drop, so error and
/// panic unwinds clean it up too; only a signal kill can leak it.
///
/// A `--state-dir` run pins it to a caller-chosen path instead: the directory is
/// reused (stale sockets from a previous run are unlinked up front) and NEVER
/// removed — the stable socket paths are the whole point (external tooling
/// attaches to `vsock-auto://<dir>/vsock.sock:<port>` while the VM runs), and the
/// caller may keep its own files (SSH keys, bind-mount sources) alongside.
struct WorkDir {
    path: PathBuf,
    pinned: bool,
    /// Advisory exclusive `flock` on the pinned dir itself, held for the run's
    /// lifetime so a second `--state-dir` run on the same path fails fast
    /// instead of unlinking the live run's sockets.
    _lock: Option<std::fs::File>,
}

impl WorkDir {
    fn create(path: PathBuf) -> Result<WorkDir> {
        std::fs::create_dir_all(&path).with_context(|| format!("creating {}", path.display()))?;
        Ok(WorkDir {
            path,
            pinned: false,
            _lock: None,
        })
    }

    /// Create-or-reuse a caller-pinned scratch dir (`--state-dir`).
    fn pinned(path: PathBuf) -> Result<WorkDir> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        // 0700 on create AND reuse: the dir holds the VM's control sockets (the
        // exec channel is a root shell in the guest), and unlike the temp-dir
        // default this path is caller-chosen — often inside a repo tree — so
        // deny other users traversal regardless of umask or a pre-existing mode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {} to 0700", path.display()))?;
        let lock = lock_state_dir(&path)?;
        remove_stale_sockets(&path)?;
        Ok(WorkDir {
            path,
            pinned: true,
            _lock: Some(lock),
        })
    }
}

/// Non-blocking exclusive `flock` on the state dir itself: a second run on the
/// same `--state-dir` would unlink the live run's sockets and fight over the
/// binds, so refuse it up front. Advisory and filesystem-local, like the other
/// locks in the tree.
fn lock_state_dir(dir: &Path) -> Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open(dir).with_context(|| format!("opening {}", dir.display()))?;
    // SAFETY: the fd is owned by `f`, which the caller keeps alive; flock
    // returns 0 or -1/errno and does not block under LOCK_NB.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            // The owning run prints its progress to the terminal that started it, not
            // here, so its pid is the only handle this caller gets on it.
            let who = flock_holder(&f).map_or_else(String::new, |h| format!(" ({h})"));
            bail!(
                "state-dir {} is in use by a live run{who} — stop that run, or pass a different --state-dir",
                dir.display()
            );
        }
        return Err(err).with_context(|| format!("locking {}", dir.display()));
    }
    Ok(f)
}

/// Best-effort identity of whoever holds `f`'s `flock`, as `pid 1234, up 19m`.
/// `/proc/locks` lists every FLOCK holder by pid and `<major>:<minor>:<inode>`
/// (major/minor in hex), which pins the owner without scanning each process's fds.
/// The VM registry would name it better, but a run records itself there only once its
/// VMM is up, and the run this message is about may still be building — so procfs is
/// the only source that covers the case, and `vk stop` has no entry to act on either.
/// `None` when procfs names nobody: the holder can exit between the refused lock and
/// this lookup, and on btrfs a subvolume's `st_dev` is not the superblock device
/// `/proc/locks` prints, so the line never matches. A holder that exits and has its pid
/// recycled before the age lookup is reported with the newcomer's age — which is why this
/// only ever garnishes a message, and nothing acts on it.
fn flock_holder(f: &std::fs::File) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let md = f.metadata().ok()?;
    let want = format!(
        "{:02x}:{:02x}:{}",
        libc::major(md.dev()),
        libc::minor(md.dev()),
        md.ino()
    );
    let pid = holder_pid(&std::fs::read_to_string("/proc/locks").ok()?, &want)?;
    Some(match crate::usage::proc_age(pid) {
        Some(age) => format!("pid {pid}, up {}", crate::vms::fmt_uptime(age.as_secs())),
        None => format!("pid {pid}"),
    })
}

/// The pid holding an `FLOCK` on `want` (`<major>:<minor>:<inode>`), out of the text of
/// `/proc/locks`. The first match is the holder: the kernel prints a lock ahead of any
/// request blocked on it, and a blocked line carries `->` where this shape wants `FLOCK`,
/// so a waiter can never be mistaken for the owner. `vk` only ever takes this lock
/// `LOCK_EX`, so the one it contends with is the only one there is to name; a foreign
/// shared `flock` on the same dir would leave the choice to line order.
fn holder_pid(locks: &str, want: &str) -> Option<i32> {
    locks.lines().find_map(|line| {
        // `108: FLOCK  ADVISORY  WRITE 1909494 fc:01:22151305 0 EOF`
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            // A lock held over NFS reports a negative pid, and one whose owner is outside
            // this pid namespace reports 0; neither names a process to point the caller at.
            [_, "FLOCK", _, _, pid, ino, ..] if *ino == want => {
                pid.parse().ok().filter(|p: &i32| *p > 0)
            }
            _ => None,
        }
    })
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if !self.pinned {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Unlink a previous run's socket files (`vsock.sock`, `vsock.sock_<port>`,
/// virtiofsd sockets, …) from a reused `--state-dir`, one level deep (the
/// per-service `svc-*` dirs hold their own). A stale unix socket file makes the
/// next bind fail, so this must run before anything listens; everything else in
/// the directory is left alone — it may be the caller's.
fn remove_stale_sockets(dir: &Path) -> Result<()> {
    let mut walk = vec![dir.to_path_buf()];
    while let Some(d) = walk.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() && d == *dir && name.starts_with("svc-") {
                walk.push(path);
            } else if ft.is_socket() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing stale {}", path.display()))?;
            }
        }
    }
    Ok(())
}

/// Pick the rootfs source for an image boot per `--source`. `auto` prefers the registry
/// (daemonless) and falls back to `docker export` only when the image is not in a registry
/// (a not-found resolve); auth/network errors propagate rather than silently using docker.
async fn resolve_source(args: &RunArgs) -> Result<Source> {
    let ca_pem = match &args.ca {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("reading {}", p.display()))?),
        None => None,
    };
    let use_oci = match args.source {
        SourceMode::Oci => true,
        SourceMode::Docker => false,
        SourceMode::Auto => {
            let exists = crate::oci::manifest_exists(
                &args.image,
                args.username.as_deref(),
                args.password.as_deref(),
                ca_pem.clone(),
                args.insecure,
            )
            .await
            .with_context(|| format!("checking the registry for {}", args.image))?;
            if !exists {
                println!(
                    "virtkit: {} is not in a registry — falling back to docker",
                    args.image
                );
            }
            exists
        }
    };
    if use_oci {
        Ok(Source::Oci {
            reference: args.image.clone(),
            username: args.username.clone(),
            password: args.password.clone(),
            ca_pem,
            insecure: args.insecure,
        })
    } else {
        Ok(Source::Docker {
            docker: "docker".into(),
            image: args.image.clone(),
        })
    }
}

/// Whether the VM booted as the primary nests: the caller's own request — `vk run --nested`,
/// or the runner's `[vm] nested` on the CI executor — or the primary service's own
/// `x-virtkit.nested`. Nesting is a capability, not a setting with a default to override, so
/// the two are ORed rather than ranked the way the sizing and init/kernel axes are, which
/// also means a primary service declaring it nests with or without the request. Shared with
/// the executor (`crate::vm`) so one rule decides it on both paths.
pub(crate) fn effective_nested(requested: bool, primary_marker: bool) -> bool {
    requested || primary_marker
}

/// The `x-virtkit.nested` of the unit booting as the primary, or `false` when no unit is
/// (`vk run --compose` with no `--primary`: compose up boots services only). A nesting
/// service that is not the primary is none of this function's business — it boots as a
/// sibling through [`crate::units::boot_unit`] with its own marker.
fn primary_nested_marker(
    compose_units: &[crate::compose::Unit],
    primary_idx: Option<usize>,
) -> bool {
    primary_idx.is_some_and(|i| compose_units[i].nested)
}

/// The directory a run's VM-registry entry is filed under: its work dir, canonicalized so a
/// run given a relative `--state-dir` and a reader arriving by another path agree on the key.
/// Both the entry itself and the service-image correction the manager makes to it go through
/// here, so the two cannot disagree about which file they mean.
fn registry_key(work: &Path) -> PathBuf {
    crate::vms::canonical(work)
}

async fn build_and_boot(
    args: &RunArgs,
    cfg: &crate::config::Config,
    state_dir: &Path,
    work: &Path,
    agent: &Path,
    kernel: &Path,
) -> Result<()> {
    // Both non-default axes boot the image from an ext4 (the modular image kernel
    // mounts /dev/vda; the image's init pivots into it), so they need an ext4 — a `-f`
    // build or a non-`--ram` image — never the pure-RAM cpio path.
    if args.init.is_image() && args.ram {
        bail!("--init {} is incompatible with --ram", args.init);
    }
    if args.kernel == KernelSource::Image && args.ram {
        bail!("--kernel image is incompatible with --ram");
    }
    // The recording outlives nothing without a state dir: an ephemeral run's work directory
    // goes with the run, log and all, and the VM is never registered for `vk atop` to find.
    if args.atop.is_some() && args.state_dir.is_none() {
        bail!(
            "--atop needs --state-dir: the recording lives in it, and `vk atop` finds the VM by it"
        );
    }
    // The image-init preinit applies the virtkit setup the image's own init won't do (the
    // guest's name, host volume mounts, symlinks, the ssh/exec serves, env, and an eth0 bridge
    // on the run-assigned address) before it hands PID 1 over. The host-exec channel, compose
    // and an interactive pty (--shell or -t) are not wired for an image PID 1 yet, and an idle
    // watchdog has nothing to power the VM off once the image owns PID 1 — reject them rather
    // than silently ignore.
    // Named on its own, because unlike the rest it has somewhere to send the operator: the
    // image's init leaves no agent at PID 1 to fork the sampler, but the reparented agent
    // still serves the exec channel, which is what an attach records over.
    if args.init.is_image() && args.atop.is_some() {
        bail!(
            "--init {} does not support --atop — boot the VM, then record it with \
             `vk atop <dir>`",
            args.init
        );
    }
    if args.init.is_image() {
        let unsupported = [
            (args.host_exec, "--host-exec"),
            (args.compose.is_some(), "--compose"),
            (args.shell, "--shell"),
            (args.tty, "-t"),
            (
                args.inactivity_timeout_secs.is_some(),
                "--inactivity-timeout",
            ),
        ]
        .into_iter()
        .filter(|(set, _)| *set)
        .map(|(_, name)| name)
        .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            bail!(
                "--init {} does not support {} yet",
                args.init,
                unsupported.join(", ")
            );
        }
    }
    // A Dockerfile boot reuses the build pipeline: build (or cache-restore, with a
    // registry) the target into an ext4, then boot it through the disk path below — so
    // `run -f Dockerfile` needs no explicit `--out` ext4. Otherwise fetch the rootfs tar
    // (docker export / registry pull) and assemble the boot medium.
    // The image's environment (PATH, etc.) applied to the guest command so it runs like
    // `docker run` does — e.g. the base image's PATH puts `cargo` in scope. For a `-f`
    // Dockerfile boot it is the target stage's accumulated ENV; for an image boot it is the
    // image's configured `Config.Env`.
    // Compose is loaded up front: a --primary primary replaces the image/-f
    // rootfs below, and the (remaining) services boot as siblings further down.
    // Timing breakdown for the run's own phases (source pull, boot media, boot, exec),
    // rendered when the run finishes. A `-f` Dockerfile build reports its own breakdown
    // separately (via the build pipeline).
    let timings = Timings::new();
    let mut compose_units: Vec<crate::compose::Unit> = match &args.compose {
        Some(p) => crate::compose::load(p)?,
        None => Vec::new(),
    };
    apply_service_sizes(&mut compose_units, &args.service_cpus, &args.service_mem)?;
    let mut image_env: Vec<(String, String)> = Vec::new();
    // The image's entrypoint, cmd and workdir, applied to the guest command like
    // `docker run`: the entrypoint is prepended to a trailing command, the workdir is
    // its cwd. `--init entrypoint` boots entrypoint+cmd as PID 1, which is the only
    // consumer of `image_cmd` — every other path takes its argv from the CLI.
    let mut image_entrypoint: Vec<String> = Vec::new();
    let mut image_cmd: Vec<String> = Vec::new();
    let mut image_workdir = String::new();
    // The --primary primary's merged config: env for the command, argv as the
    // default command, hostname for the guest.
    let mut primary: Option<vk_core::runcfg::RunConfig> = None;
    let mut primary_idx: Option<usize> = None;
    let mut primary_hostname: Option<String> = None;
    let mut primary_volumes: Vec<crate::compose::Volume> = Vec::new();
    // The primary's run user (a `-f` build's final image USER, or a --primary
    // service's merged user): a clean image is byte-clean (no injected
    // /etc/virtkit/user), so the boot config is the only carrier — dropping it
    // leaves the guest agent without a run user and the host-exec socket unchowned
    // (root-only). Set on both primary paths below; empty means root.
    let mut primary_user = String::new();
    // The --primary primary's own init/kernel axes (from its `x-virtkit` marker),
    // merged with the CLI axes below. None for a non-compose / non-primary boot.
    let mut primary_axes: Option<(InitSource, KernelSource)> = None;
    // Resolve the --primary primary's index up front — it drives both the unified compose
    // build below and the sibling provisioning later.
    if let Some(name) = &args.primary {
        primary_idx = Some(resolve_primary(&compose_units, name)?);
    }

    // Build every compose image the run needs in ONE unified build — the --primary primary
    // (-> root.ext4) and every sibling (-> svc-<name>/image.ext4) — so stages shared across
    // the compose Dockerfile build or restore once for the whole set instead of once per
    // pass. Empty (and skipped) for a non-compose boot; the primary's config is read out of
    // it just below, the siblings' by plan_services further down.
    let compose_built = if args.compose.is_some() {
        build_compose_images(args, work, kernel, agent, &compose_units, primary_idx)?
    } else {
        std::collections::HashMap::new()
    };

    let dockerfile_ext4 = if let Some(name) = &args.primary {
        let unit = &compose_units[primary_idx.expect("primary_idx resolved when --primary set")];
        let built = compose_built
            .get(name)
            .with_context(|| format!("internal: primary service {name} not built"))?;
        let cfg = crate::compose::merged_config(&built.config, unit);
        image_env = cfg.env.clone();
        image_entrypoint = cfg.entrypoint.clone();
        image_cmd = cfg.cmd.clone();
        image_workdir = cfg.workdir.clone();
        primary_user = cfg.user.clone();
        primary_hostname = Some(unit.hostname.clone());
        primary_volumes = unit.volumes.clone();
        primary_axes = Some((unit.init, unit.kernel.clone()));
        primary = Some(cfg);
        Some(work.join("root.ext4"))
    } else if args.dockerfiles.is_empty() {
        None
    } else {
        let out = work.join("root.ext4");
        let opts = crate::build::Options {
            dockerfiles: args.dockerfiles.clone(),
            target: args.target.clone(),
            contexts: args.contexts.clone(),
            build_contexts: args.build_contexts.clone(),
            out: Some(out.clone()),
            out_disk: None,
            print_plan: false,
            cloud_hypervisor: Some(args.cloud_hypervisor.clone()),
            kernel: Some(kernel.to_path_buf()),
            agent: Some(agent.to_path_buf()),
            cache_registry: args.cache_registry.clone(),
            cache_insecure: args.cache_insecure,
            cache_auth: Default::default(),
            build_cache: crate::build::BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: args.build_args.clone(),
            net: args.build_net.clone(),
            // `--build-audit-egress` audits this `-f` build's RUN egress; `--audit-egress`
            // (handled below) audits the booted guest — the same split as --net/--build-net.
            audit: args.build_audit_egress,
            require_cached: args.require_cached,
            build_jobs: cfg.build.jobs,
            debug: false,
            progress_sink: None,
        };
        let built = crate::build::build(&opts)?;
        primary_user = built.config.user;
        image_env = built.config.env;
        image_entrypoint = built.config.entrypoint;
        image_cmd = built.config.cmd;
        image_workdir = built.config.workdir;
        Some(out)
    };

    // What this run costs the host, reported with the breakdown below (see `usage`). Started
    // here, after any `-f`/`--primary` build: that build reports its own line, and a window
    // spanning it would nest the two meters — a nested pair is attributable to neither, so
    // neither line would print. An eagerly started `build:` sibling below can still build
    // inside this window, which withholds both lines for the same reason.
    let meter = crate::usage::Meter::start();

    // Effective init/kernel axes for the boot. Precedence, per the uniform-axes model:
    //   1. a non-`Default` CLI `--init`/`--kernel` overrides every unit (a run-wide force);
    //   2. otherwise the --primary primary's own marker axes apply;
    //   3. absent both → `Default` (today's behavior).
    // Non-compose boots (plain image / `-f`) have no marker, so they keep the CLI axes.
    let (marker_init, marker_kernel) = primary_axes
        .clone()
        .unwrap_or((InitSource::Default, KernelSource::Default));
    let eff_init = if args.init != InitSource::Default {
        args.init
    } else {
        marker_init
    };
    let eff_kernel = if args.kernel != KernelSource::Default {
        args.kernel.clone()
    } else {
        marker_kernel
    };
    // The CLI axis was rejected far above, before the build; this catches a --primary
    // service whose own x-virtkit marker selects an image PID 1, checked on the merged axes
    // just computed above (like the --ram guard a few lines below).
    if args.inactivity_timeout_secs.is_some() && eff_init.is_image() {
        bail!("a service's x-virtkit `init: {eff_init}` is incompatible with --inactivity-timeout");
    }
    // Effective primary sizing, same precedence as the axes: an explicit --cpus/--mem
    // overrides the --primary service's own x-virtkit sizing (which already carries
    // any --service-cpus/--service-mem override); absent both, the run defaults.
    let (marker_cpus, marker_mem) = primary_idx
        .map(|i| (compose_units[i].cpus, compose_units[i].mem.clone()))
        .unwrap_or((None, None));
    let cpus = args
        .cpus
        .or(marker_cpus)
        .unwrap_or(crate::units::DEFAULT_CPUS);
    let mem = args
        .mem
        .clone()
        .or(marker_mem)
        .unwrap_or_else(|| crate::units::DEFAULT_MEM.to_string());
    let nested = effective_nested(
        args.nested,
        primary_nested_marker(&compose_units, primary_idx),
    );
    // The pinned/explicit kernel `fullvm::prepare` boots on for a non-image kernel axis
    // (Default or Path). A CLI `--kernel <path>` was already resolved into `kernel` by
    // `run()`; a marker `kernel: <path>` (when the CLI left kernel Default) is resolved
    // here so a per-service kernel file also works for the primary.
    let pinned_kernel: PathBuf = match &eff_kernel {
        KernelSource::Path(p) if args.kernel == KernelSource::Default => p.clone(),
        _ => kernel.to_path_buf(),
    };
    // The effective-axes counterpart of the CLI `--ram` guards above: a primary whose
    // marker (not the CLI flag) selects an image axis also needs an ext4, never the cpio
    // path. `--primary` forces the ext4 disk path anyway, so this only ever fires if that
    // invariant is broken — a belt-and-braces check on the merged axes.
    if args.ram && (eff_init.is_image() || eff_kernel == KernelSource::Image) {
        let mut axes = Vec::new();
        if eff_init.is_image() {
            axes.push(format!("`init: {eff_init}`"));
        }
        if eff_kernel == KernelSource::Image {
            axes.push("`kernel: image`".to_string());
        }
        bail!(
            "a service's x-virtkit {} is incompatible with --ram",
            axes.join(" / ")
        );
    }

    // 1. the rootfs source (docker export or registry pull) for an image boot, unless a
    // Dockerfile build already produced the ext4 above. The rootfs tar itself never
    // exists as a file — step 2 streams it straight into the cpio/ext4 builder.
    let source = match dockerfile_ext4 {
        None => {
            let t_source = Instant::now();
            let source = resolve_source(args).await?;
            timings.record(Phase::SourcePull, "", t_source.elapsed());
            // Inherit the image's configured environment (PATH etc.), entrypoint and
            // workdir for the guest command, as `docker run` does.
            let cfg = source.run_config().await?;
            image_env = cfg.env;
            image_entrypoint = cfg.entrypoint;
            image_cmd = cfg.cmd;
            image_workdir = cfg.workdir;
            Some(source)
        }
        Some(_) => None,
    };
    // Every path that can carry an image config has now read one, so this is where the
    // entrypoint axis can be checked: it has PID 1 exec the image's entrypoint, and an image
    // naming none leaves it nothing to become — the guest would boot the init instead, the
    // silent skip this axis exists to end. Refused here, where the operator reads it, rather
    // than warned about on a guest console a successful run never prints. Read off the
    // merged config, so a compose `entrypoint:`/`command:` counts as naming one.
    if eff_init == InitSource::Entrypoint && image_entrypoint.is_empty() && image_cmd.is_empty() {
        // The axis reaches here from the flag or from a --primary service's marker, never
        // both: `--init entrypoint` with `--compose` was rejected far above, and --primary
        // implies --compose. Name whichever one the operator actually wrote.
        let axis = if args.init == InitSource::Entrypoint {
            "--init entrypoint"
        } else {
            "a service's x-virtkit `init: entrypoint`"
        };
        bail!("{axis} needs an image with an ENTRYPOINT or CMD — this one declares neither");
    }
    // --env/--env-file extras, upserted so they win over the image env — both in
    // `drive`'s exports and in the guest's own env (the media below carry the
    // merged list: the boot config for a clean -f/--primary image, an injected
    // /etc/virtkit/env capture for a converted one).
    for (k, v) in &args.env {
        match image_env.iter_mut().find(|(ek, _)| ek == k) {
            Some(e) => e.1 = v.clone(),
            None => image_env.push((k.clone(), v.clone())),
        }
    }
    // Every carrier of this list (drive's exports, the boot config, the
    // /etc/virtkit/env capture) is line-oriented in the guest: drop entries an
    // embedded newline would split into bogus extra lines — loudly.
    image_env.retain(|(k, v)| {
        let ok = !k.contains('\n') && !v.contains('\n');
        if !ok {
            eprintln!("virtkit: skipping env var {k:?} (embedded newline)");
        }
        ok
    });

    // 2. assemble the boot medium (virtkit-agent injected as PID 1). With the libkrun
    // backend the media are unlinked scratch fds — `media` keeps them open (their
    // /proc/self/fd paths must resolve until the VMM child has spawned), `pass_fds`
    // hands them across the exec — so a killed run cannot leak them. The external
    // cloud-hypervisor keeps named files in `work`.
    let mut media: Vec<crate::scratch::ScratchFile> = Vec::new();
    let mut pass_fds: Vec<i32> = Vec::new();
    let anon = crate::vmm::libkrun_selected();
    let mut medium = |name: &str| -> Result<PathBuf> {
        if !anon {
            return Ok(work.join(name));
        }
        let s = crate::scratch::scratch(work, name)?;
        let path = s.path.clone();
        pass_fds.push(s.fd());
        media.push(s);
        Ok(path)
    };
    // The effective env as capture-file lines, injected into a converted image's
    // rootfs at /etc/virtkit/env (a clean `-f` image carries it in the boot config
    // instead). Same format as the conversion capture: raw KEY=VALUE per line.
    let env_capture = work.join("env.capture");
    let mut injects: Vec<(&str, &Path, u16)> =
        vec![(crate::initramfs::CMDRUNNER_PATH, agent, 0o755)];
    if !image_env.is_empty() {
        let text: String = image_env
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect();
        // env values may be secrets (the reason they stay off the cmdline):
        // keep the host-side capture private too.
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&env_capture)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .with_context(|| format!("writing {}", env_capture.display()))?;
        injects.push(("etc/virtkit/env", &env_capture, 0o644));
    }
    let t_media = Instant::now();
    // The kernel the VM boots on. Normally the pinned kernel passed in; when the
    // kernel axis is `image`, fullvm::prepare below overrides it with the kernel
    // extracted from the image.
    let mut boot_kernel = pinned_kernel.clone();
    // Either non-default axis boots via the preinit initramfs: the image's own init
    // needs the agent-as-/init handoff, and a modular image kernel needs the module
    // initramfs. A default/default run keeps the existing non-image branches below.
    // The axes are the merged effective values (CLI force > primary marker > default).
    let (disks, initramfs, mut cmdline): (Vec<crate::vmm::Disk>, Option<PathBuf>, String) =
        if eff_init.is_image() || eff_kernel == KernelSource::Image {
            // Boot via the preinit initramfs. First get the raw ext4: a `-f` build already
            // produced one (dockerfile_ext4), otherwise build root.ext4 from the image
            // source exactly as the disk path below does.
            let ext4 = if let Some(ext4) = &dockerfile_ext4 {
                ext4.clone()
            } else {
                println!("virtkit: building ext4 rootfs");
                let rootfs = medium("root.ext4")?;
                let source = source.as_ref().expect("an image boot resolved a source");
                source
                    .stream_tar(work, |tar, hints| {
                        // The preinit boot keeps the image byte-clean: the agent rides the
                        // preinit initramfs, not the rootfs, so nothing is injected here. Leave a
                        // small free-space margin so the exact-fit estimate never trips.
                        crate::ext4::build_from_tar_stream(
                            tar,
                            &[],
                            hints.image_bytes(),
                            16384, // 64 MiB slack for the guest's own writes at boot
                            Some(hints.inode_count()),
                            &crate::ext4::FsId {
                                with_journal: true,
                                ..Default::default()
                            },
                            &rootfs,
                        )
                    })
                    .await?;
                rootfs
            };
            // Build the preinit initramfs (agent as /init that insmods any modules, pivots,
            // then execs whatever the init axis names); with --kernel image also extract the
            // image's kernel. The boot config carries what the agent needs before it hands
            // PID 1 over: the effective env, and the image's entrypoint+cmd+workdir, which
            // `--init entrypoint` execs as PID 1 (the other axes exec /sbin/init and ignore
            // them).
            let boot_cfg = vk_core::runcfg::RunConfig {
                env: image_env.clone(),
                user: primary_user.clone(),
                workdir: image_workdir.clone(),
                entrypoint: image_entrypoint.clone(),
                cmd: image_cmd.clone(),
                ..Default::default()
            };
            let kernel_medium = medium("vmlinuz")?;
            let preinit = medium("initramfs.cpio")?;
            let boot = crate::fullvm::prepare(
                &ext4,
                agent,
                &kernel_medium,
                &preinit,
                Some(&boot_cfg),
                &eff_kernel,
                &pinned_kernel,
            )?;
            boot_kernel = boot.kernel;
            // throwaway rw qcow2 overlay over the ro raw ext4 (rw raw errors on tmpfs)
            let overlay = medium("overlay.qcow2")?;
            crate::qcow2::create_overlay(&overlay, &ext4)?;
            // Base handoff cmdline; the per-axis tokens are appended below so the guest
            // agent and the console gating can each read the axis that concerns them.
            let mut kcmd = format!(
                "console=ttyS0 pci=conf1 VIRTKIT_PIVOT=/dev/vda \
                 VIRTKIT_VSOCK_PORT={VSOCK_PORT} VIRTKIT_HOSTNAME={}",
                primary_hostname.as_deref().unwrap_or("vm")
            );
            // A modular image kernel has no early hvc0: keep console on ttyS0 (see the
            // console gating in libkrun_sys). The pinned kernel has hvc0, so kernel==default
            // leaves the rewrite in place.
            if eff_kernel == KernelSource::Image {
                kcmd.push_str(" VIRTKIT_KERNEL=image");
            }
            // Who takes PID 1 after the handoff. When init==default the agent stays PID 1
            // and pivots via the existing VIRTKIT_PIVOT path — the fragment is then empty.
            kcmd.push_str(&eff_init.handoff_tokens());
            (
                vec![crate::vmm::Disk::overlay(overlay)],
                Some(boot.initramfs),
                kcmd,
            )
        } else if let Some(ext4) = &dockerfile_ext4 {
            // A Dockerfile build exports a *clean* ext4 (no agent baked in). Boot it the way
            // the builder boots its own stages: a minimal initramfs holds the agent as `/init`,
            // which pivots into the ext4 at /dev/vda — so the booted image stays byte-clean.
            // The boot config carries the effective env (stage/service ENV + --env
            // extras): the agent applies it and materializes /etc/virtkit/env for login
            // shells, keeping the image itself byte-clean.
            let cpio = medium("initramfs.cpio")?;
            let boot_cfg = vk_core::runcfg::RunConfig {
                env: image_env.clone(),
                user: primary_user.clone(),
                ..Default::default()
            };
            crate::initramfs::build_agent_initramfs_with_config(agent, Some(&boot_cfg), &cpio)?;
            // throwaway rw qcow2 overlay over the ro raw ext4 (rw raw errors on tmpfs)
            let overlay = medium("overlay.qcow2")?;
            crate::qcow2::create_overlay(&overlay, ext4)?;
            (
                vec![crate::vmm::Disk::overlay(overlay)],
                Some(cpio),
                format!(
                    "console=ttyS0 rdinit=/init VIRTKIT_PIVOT=/dev/vda \
                     VIRTKIT_HOSTNAME={} VIRTKIT_VSOCK_PORT={VSOCK_PORT}",
                    primary_hostname.as_deref().unwrap_or("vm")
                ),
            )
        } else if !args.ram {
            println!("virtkit: building ext4 rootfs");
            let rootfs = medium("root.ext4")?;
            let source = source.as_ref().expect("an image boot resolved a source");
            source
                .stream_tar(work, |tar, hints| {
                    crate::ext4::build_from_tar_stream(
                        tar,
                        &injects,
                        hints.image_bytes(),
                        0,
                        Some(hints.inode_count()),
                        &crate::ext4::FsId {
                            with_journal: true,
                            ..Default::default()
                        },
                        &rootfs,
                    )
                })
                .await?;
            // throwaway rw qcow2 overlay over the ro raw ext4 (rw raw errors on tmpfs)
            let overlay = medium("overlay.qcow2")?;
            crate::qcow2::create_overlay(&overlay, &rootfs)?;
            (
                vec![crate::vmm::Disk::overlay(overlay)],
                // no initrd: the kernel mounts /dev/vda (ext4) directly
                None,
                format!(
                    "console=ttyS0 root=/dev/vda rw rootfstype=ext4 \
                     init=/usr/local/bin/vk-agent \
                     VIRTKIT_HOSTNAME=vm VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
                ),
            )
        } else {
            println!("virtkit: building cpio initramfs");
            let cpio = medium("initramfs.cpio")?;
            let source = source.as_ref().expect("an image boot resolved a source");
            source
                .stream_tar(work, |tar, _| {
                    crate::initramfs::build_initramfs_injecting(tar, &injects, &cpio)
                })
                .await?;
            // The kernel unpacks the cpio into the rootfs tmpfs, which is capped at
            // half of MemTotal — and MemTotal itself excludes the RAM still holding
            // the archive. So a cpio boot needs roughly (2 * unpacked + archive) ≈
            // three times the initramfs size, plus working room; with less, the
            // unpack hits ENOSPC and the guest dies before its console comes up
            // (an empty-log "exited during boot"). Refuse up front instead.
            let initramfs_mib = std::fs::metadata(&cpio)?.len() >> 20;
            let need_mib = initramfs_mib * 3 + 384;
            if let Some(mem_mib) = parse_mem_mib(&mem)
                && mem_mib < need_mib
            {
                bail!(
                    "the image unpacks to a {initramfs_mib} MiB initramfs, which does not fit \
                     in --mem {} — pass --mem {}G, or drop --ram to boot from a disk",
                    mem,
                    need_mib.div_ceil(1024),
                );
            }
            (
                Vec::new(),
                Some(cpio),
                format!(
                    "console=ttyS0 rdinit=/usr/local/bin/vk-agent VIRTKIT_HOSTNAME=vm \
                     VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
                ),
            )
        };
    timings.record(Phase::BootMedia, "", t_media.elapsed());

    // The agent is PID 1 and receives no usable argv, so its exec-idle watchdog is
    // configured through the kernel cmdline. Zero deliberately adds no watchdog while
    // still making the host retain the detached VM after its startup command.
    if let Some(timeout) = args.inactivity_timeout_secs.filter(|timeout| *timeout > 0) {
        cmdline.push_str(&format!(" VIRTKIT_INACTIVITY_TIMEOUT={timeout}"));
    }

    // SSH-agent forwarding: tell the guest agent to present SSH_AUTH_SOCK and relay it over
    // a vsock port, which the host side (started below) bridges to the host's real agent —
    // either the whole agent (--ssh-agent) or a key-filtered subset (--ssh-host).
    let vsock = work.join("vsock.sock");
    let ssh = ssh_agent_setup(args);
    if ssh.is_some() {
        cmdline.push_str(&format!(" VIRTKIT_SSH_AGENT_PORT={SSH_AGENT_VSOCK_PORT}"));
    }

    // --ssh: the guest agent serves SSH over vsock (no sshd in the image). The
    // authorized keys ride the kernel cmdline whitespace-free as `type:base64`;
    // sessions run as --ssh-user (default root — the only user every image is
    // guaranteed to have).
    if args.ssh {
        let keys = if args.ssh_keys.is_empty() {
            default_ssh_pubkeys()?
        } else {
            args.ssh_keys.clone()
        };
        cmdline.push_str(&format!(
            " VIRTKIT_SSH=1 VIRTKIT_SSH_KEYS={} VIRTKIT_SSH_USER={}",
            encode_ssh_keys(&keys)?,
            args.ssh_user
        ));
    }

    // Compose services: sibling unit VMs on the run switch, resolvable by alias
    // over its DNS, torn down with the run.
    let planned = plan_services(args, cfg, state_dir, work, &compose_units, primary_idx)?;
    // With sibling services under management, the agent exposes their control
    // plane at /run/vk/services (a FUSE bridge to the manager over vsock).
    if !planned.units.is_empty() {
        cmdline.push_str(" VIRTKIT_CTL=1");
    }

    // Snapshot the sibling services for the VM registry (see vms.rs) before the manager takes
    // ownership of `planned`: while running, each serves its agent at `<svc-dir>/vsock.sock` so
    // `vk exec --service` can reach it, and a `build:` service carries its recipe so `vk list
    // --stale` folds its image into the freshness check. Same context/build-arg derivation as
    // `compose_build_units`. The recipe's image is the address provisioning predicted, which is
    // all that is known at this point; every `build:` sibling materializes at its first start
    // and adopts whatever entry its build settles on, so the address is taken from the manager
    // below for the starts that have already run, and corrected by `vms::note_service_image`
    // for the ones that come later over the control plane.
    let mut service_entries: Vec<crate::vms::ServiceEntry> = planned
        .units
        .iter()
        .map(|(prov, dir, unit)| {
            let stale_recipe = match &unit.source {
                crate::compose::Source::Build {
                    dockerfiles,
                    context,
                    build_contexts,
                    target,
                    args: unit_args,
                } => {
                    let mut build_args = args.build_args.clone();
                    build_args.extend(unit_args.iter().cloned());
                    Some(crate::vms::StaleRecipe {
                        dockerfiles: dockerfiles.clone(),
                        contexts: vec![context.clone(); dockerfiles.len()],
                        build_contexts: build_contexts.clone(),
                        build_args,
                        target: target.clone(),
                        root_ext4: prov.ext4.clone(),
                    })
                }
                crate::compose::Source::Image(_) => None,
            };
            crate::vms::ServiceEntry {
                name: prov.name.clone(),
                exec_addr: format!("vsock-auto://{}/vsock.sock:{VSOCK_PORT}", dir.display()),
                stale_recipe,
            }
        })
        .collect();

    // --host-exec: the guest agent presents /run/vk/host.sock, relayed over vsock
    // to a host-side `vk-agent serve` (spawned after boot, below).
    if args.host_exec {
        cmdline.push_str(&format!(" VIRTKIT_HOST_EXEC_PORT={HOST_EXEC_PORT}"));
    }

    // Networking: a userspace `vk switch` over vsock gives the guest egress (the agent
    // forks a tap bridged to it and takes the static address from the cmdline fragment).
    // With services it also pre-listens on their sockets and answers their aliases.
    let mut switch = if args.net {
        // Opt-in credential proxy: run a host-local proxy that injects the runner's
        // registry credentials, and redirect the guest's `registry.vk` (a sentinel
        // class-E address the switch special-cases) to it — the job stays credential-free.
        let mut hosts = planned.hosts.clone();
        let registry_proxy = match &args.registry_proxy {
            Some(upstream) => {
                const SENTINEL: std::net::Ipv4Addr = std::net::Ipv4Addr::new(240, 0, 0, 1);
                let cfg = crate::regproxy::ProxyCfg::from_parts(
                    upstream,
                    args.username.clone(),
                    args.password.clone(),
                    args.ca.clone(),
                    args.insecure,
                )?;
                let addr = crate::regproxy::spawn(cfg).await?;
                hosts.push(("registry.vk".to_string(), SENTINEL.to_string()));
                cmdline.push_str(" VIRTKIT_REGISTRY=registry.vk");
                Some((SENTINEL, addr))
            }
            None => None,
        };
        let (child, frag) = spawn_vm_switch(
            &vsock,
            work,
            NET_VSOCK_PORT,
            &[],
            &[],
            &planned.listen,
            &hosts,
            &planned.reservations,
            registry_proxy,
            args.audit_egress.then(|| work.join(AUDIT_LOG)),
            Some(work.join(NET_BYTES)),
            // Dev `vk run` egress is unrestricted (no allowlist plumbed here).
            false,
        )
        .await?;
        cmdline.push_str(&frag);
        Some(child)
    } else {
        if args.registry_proxy.is_some() {
            bail!(
                "--registry-proxy requires --net: the guest reaches the credential proxy \
                 through the switch's sentinel redirect, which only exists with networking"
            );
        }
        None
    };

    // Hand every declared unit to the manager, then boot the eager set through
    // it, dependencies first, once the switch listens. No readiness wait (the
    // compose contract): the run command retries its first connect. The same
    // manager later serves the primary's control plane (start/stop on demand).
    let manager = if planned.units.is_empty() {
        None
    } else {
        let (gw, _, _) = crate::net::switch_addrs(RUN_SUBNET)?;
        Some(std::sync::Arc::new(crate::manager::Manager::new(
            kernel.to_path_buf(),
            args.cloud_hypervisor.clone(),
            NET_VSOCK_PORT,
            gw,
            agent.to_path_buf(),
            manager_build_opts(args, kernel, agent),
            crate::manager::ManagerDirs {
                cache: state_dir.to_path_buf(),
                // Only a pinned run files a registry entry, so only a pinned run has one to
                // correct — see the `register` call below.
                run: args.state_dir.as_ref().map(|_| registry_key(work)),
            },
            cfg.image_cache_idle(),
            planned.units,
        )))
    };
    if let Some(mgr) = &manager {
        for name in &planned.start {
            let reply = mgr.start(name);
            if !reply.ok {
                mgr.stop_all();
                if let Some(mut c) = switch.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                bail!("booting service {name}: {}", reply.message);
            }
            println!("virtkit: service {name}: {}", reply.message);
        }
    }

    // Working directory: share a host dir read-write over virtiofs at WORKDIR_MOUNT (no uid
    // map — virtiofsd's `--sandbox=none` writes back as the host
    // user), so the guest command reads/writes the live tree and its outputs land on the
    // host. The command then runs with its cwd there (see `drive`). virtio-fs needs shared
    // guest memory, so `mem` gains `shared=on`.
    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    let mut virtiofsds: Vec<Child> = Vec::new();
    let mut virtiofs = String::new();
    if let Some(host_dir) = &args.workdir {
        let sock = work.join("workdir.fs.sock");
        // libkrun mounts host_dir directly (built-in virtio-fs); only cloud-hypervisor
        // needs the external virtiofsd on `sock`.
        if !crate::vmm::libkrun_selected() {
            virtiofsds.push(crate::spawn::spawn_virtiofsd(
                &sock,
                host_dir,
                false,
                &[],
                &[],
            )?);
        }
        virtiofs.push_str(&format!("work:{WORKDIR_MOUNT}"));
        shares.push(crate::vmm::FsShare {
            tag: "work".into(),
            socket: sock,
            host_dir: host_dir.clone(),
            read_only: false,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        });
    }
    // A --primary primary gets its compose volumes, and any primary its `--volume`
    // flags, exactly like a sibling unit would: bind mounts over virtiofs.
    // Persistent state (a dev VM's ~/.vscode-server, say) is whatever binds to a
    // host dir — the VM itself stays throwaway.
    // A single-file bind can't be mounted onto the guest file path (virtio-fs shares a
    // directory); its share is served by the single-file fs, mounted at a hidden dir, and
    // symlinked into place — collected here and merged into VIRTKIT_SYMLINKS below.
    let mut file_bind_links: Vec<(String, String)> = Vec::new();
    // Tags the agent should mount behind a tmpfs-backed overlay (`-v host:guest:overlay`).
    let mut overlay_tags: Vec<String> = Vec::new();
    for (i, vol) in primary_volumes.iter().chain(&args.volumes).enumerate() {
        let tag = format!("vol{i}");
        let sock = work.join(format!("vfsd-{tag}.sock"));
        // cloud-hypervisor serves each share through an external virtiofsd (libkrun serves in
        // process). Single-file binds work on both: the single-file fs runs in-process under
        // libkrun and inside `vk virtiofsd` over vhost-user under cloud-hypervisor.
        if !crate::vmm::libkrun_selected() {
            virtiofsds.push(crate::spawn::spawn_virtiofsd(
                &sock,
                &vol.host,
                vol.read_only,
                &[],
                &[],
            )?);
        }
        let mount_at = if vol.is_file {
            // virtio-fs shares a directory, so mount the single-file share at a hidden dir and
            // symlink the guest target to the file inside it.
            let base = vol
                .host
                .file_name()
                .and_then(|n| n.to_str())
                .with_context(|| {
                    format!("single-file bind {}: bad file name", vol.host.display())
                })?;
            let mp = format!("/run/vk/filebind-{i}");
            file_bind_links.push((format!("{mp}/{base}"), vol.guest.clone()));
            mp
        } else {
            vol.guest.clone()
        };
        if !virtiofs.is_empty() {
            virtiofs.push(',');
        }
        virtiofs.push_str(&format!("{tag}:{mount_at}"));
        if vol.overlay {
            overlay_tags.push(tag.clone());
        }
        shares.push(crate::vmm::FsShare {
            tag,
            socket: sock,
            host_dir: vol.host.clone(),
            read_only: vol.read_only,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        });
    }
    // `--atop`: record what this guest does from boot, exactly as a CI job's guest is
    // recorded. The archive directory rides its own share, kept out of VIRTKIT_VIRTIOFS
    // on purpose: the cmdline knob names the tag, and the agent mounts it before
    // anything else runs in the guest, so even the boot is covered.
    // Held for as long as the VM runs: the exclusive lock `vk atop`'s attach takes before it
    // records, so no attach can truncate this recording or start a second sampler beside it.
    // The lock, not the registry entry, is what closes that door — the entry is written after
    // the VMM starts, and an attach in the gap would find nothing to warn it off.
    let _atop_lock;
    let atop_log = match args.atop {
        None => None,
        Some(secs) => {
            let dir = work.join("atop");
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            let log = dir.join(vk_core::atop::LOG_NAME);
            // A fresh boot is a fresh recording: the guest appends, and a log left by a
            // previous run of this state dir would read as two boots run together.
            if let Err(e) = std::fs::remove_file(&log)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e).with_context(|| format!("removing stale {}", log.display()));
            }
            // Created here rather than left to the guest, so the lock below is held from
            // before the VM exists — the guest then appends to this same file.
            let held = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                // As the guest would have created it: the guest appends to this file, and
                // the share maps its writes onto this user.
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&log)
                .with_context(|| format!("creating {}", log.display()))?;
            // SAFETY: the fd is owned by `held`, which outlives the call; flock returns 0
            // or -1. The lock goes when this process does, which is when the VM does.
            use std::os::unix::io::AsRawFd as _;
            if unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!(
                    "{} is already being recorded — stop the `vk run` or `vk atop` that owns it",
                    log.display()
                );
            }
            _atop_lock = held;
            let sock = work.join("atop.fs.sock");
            if !crate::vmm::libkrun_selected() {
                virtiofsds.push(crate::spawn::spawn_virtiofsd(&sock, &dir, false, &[], &[])?);
            }
            shares.push(crate::vmm::FsShare {
                tag: vk_core::atop::TAG.into(),
                socket: sock,
                host_dir: dir,
                read_only: false,
                uid_map: Vec::new(),
                gid_map: Vec::new(),
            });
            cmdline.push_str(&vk_core::atop::cmdline_knob(secs));
            println!(
                "virtkit: recording guest stats every {secs}s -> {} (`vk atop` to watch)",
                log.display()
            );
            Some(log)
        }
    };
    if !virtiofs.is_empty() {
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS={virtiofs}"));
    }
    if !overlay_tags.is_empty() {
        cmdline.push_str(&format!(
            " VIRTKIT_VIRTIOFS_OVERLAY={}",
            overlay_tags.join(",")
        ));
    }
    // In-guest symlinks, created by the agent after the mounts: explicit `--symlink`s plus one
    // per single-file bind (target -> the file inside its hidden single-file share mount). A
    // dangling source is skipped guest-side.
    let symlink_specs: Vec<String> = args
        .symlinks
        .iter()
        .chain(file_bind_links.iter())
        .map(|(src, dest)| format!("{src}:{dest}"))
        .collect();
    if !symlink_specs.is_empty() {
        cmdline.push_str(&format!(" VIRTKIT_SYMLINKS={}", symlink_specs.join(",")));
    }
    let shared_mem = !shares.is_empty();

    // 3. boot
    let console = work.join("console.log");
    let vmm = crate::vmm::selected(&args.cloud_hypervisor);
    let addr = crate::vmm::exec_addr(&vsock, VSOCK_PORT);
    println!("virtkit: booting {} (cpus={cpus}, mem={mem})", vmm.name());
    // exec channel always; the switch and ssh-agent bridges only when set up above.
    let mut vsock_ports = vec![crate::vmm::VsockPort::exec(&vsock, VSOCK_PORT)];
    if args.net {
        vsock_ports.push(crate::vmm::VsockPort::bridge(&vsock, NET_VSOCK_PORT));
    }
    if ssh.is_some() {
        vsock_ports.push(crate::vmm::VsockPort::bridge(&vsock, SSH_AGENT_VSOCK_PORT));
    }
    // --ssh, host→guest: registered on the base socket like the exec channel, so
    // the connect address is `vsock-auto://<vsock.sock>:2222` on either backend
    // (libkrun gets a per-port listener; cloud-hypervisor ignores the entry —
    // its hybrid socket serves every port).
    if args.ssh {
        vsock_ports.push(crate::vmm::VsockPort::exec(&vsock, SSH_VSOCK_PORT));
    }
    // Control plane (guest→host): the primary dials CONTROL_PORT to reach the
    // service manager; only wired when compose services are declared.
    if manager.is_some() {
        vsock_ports.push(crate::vmm::VsockPort::bridge(
            &vsock,
            vk_core::fleetctl::CONTROL_PORT,
        ));
    }
    // Host-exec (guest->host): the guest's /run/vk/host.sock forwarder dials
    // HOST_EXEC_PORT, bridged to the `vk-agent serve` spawned below.
    if args.host_exec {
        vsock_ports.push(crate::vmm::VsockPort::bridge(&vsock, HOST_EXEC_PORT));
    }
    // The VM's process name follows the boot target: a --primary compose service, a -f
    // Dockerfile stage (the target, or "build" for the default last stage), or the image ref.
    let unit_name = if let Some(name) = &args.primary {
        name.clone()
    } else if !args.dockerfiles.is_empty() {
        args.target.clone().unwrap_or_else(|| "build".to_string())
    } else {
        args.image
            .rsplit('/')
            .next()
            .unwrap_or(&args.image)
            .to_string()
    };
    // --disk: raw host images appended after any rootfs disk (so vdb, vdc, … — vda
    // first under --ram, which seeds no rootfs disk), so the guest can
    // partition/mkfs/install into a disk image directly. Paths are canonicalized so a
    // relative --disk resolves against the caller's cwd like the rootfs media do.
    let mut disks = disks;
    for (path, readonly) in &args.extra_disks {
        let abs = std::fs::canonicalize(path)
            .with_context(|| format!("--disk {}: cannot access", path.display()))?;
        disks.push(crate::vmm::Disk::raw(abs, *readonly));
    }
    let spec = crate::vmm::VmSpec {
        kernel: boot_kernel,
        cmdline,
        disks,
        initramfs,
        shares,
        vsock_cid: 3,
        vsock_socket: vsock.clone(),
        vsock_ports,
        cpus,
        mem: mem.clone(),
        shared_mem,
        net: crate::vmm::Net::None,
        balloon: true,
        serial_log: console.clone(),
        console_serial: args.console_serial,
        pmu: args.pmu,
        nested,
        api_socket: None,
        pass_fds,
        proc_name: crate::vmm::resolve_proc_name(&unit_name),
    };
    // Control server on the primary's hybrid-vsock control socket — only the
    // primary's guest can reach it, so the control plane is scoped to this run.
    if let Some(mgr) = &manager {
        let ctl = crate::vmm::hybrid_socket(&vsock, vk_core::fleetctl::CONTROL_PORT);
        let mgr = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::manager::control_server(&ctl, mgr).await {
                eprintln!("virtkit: control server exited: {e:#}");
            }
        });
    }

    let mut ch = match spawn_vmm(vmm.as_ref(), &spec) {
        Ok(ch) => ch,
        // The --net switch and the virtiofsds (--workdir plus any --primary compose
        // volumes) are already spawned; kill them so a failed boot does not leak
        // host-side children (a leaked `vk virtiofsd` would, e.g., hold this binary's
        // file busy for the next build).
        Err(e) => {
            if let Some(mgr) = &manager {
                mgr.stop_all();
            }
            for mut child in virtiofsds.drain(..).chain(switch.take()) {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(e);
        }
    };

    // Pre-declared so every post-VMM error site can route through teardown_run,
    // which needs these even when the ssh / host-exec steps have not run.
    let mut ssh_forward: Option<Child> = None;
    let mut host_exec_serve: Option<Child> = None;

    // Record the VM in the host-side registry so `vk list`/`vk stop` can find it by the
    // directory it was launched from. Only pinned (`--state-dir`) runs are tracked: they
    // expose this stable exec socket and hold the state-dir lock the registry probes for
    // liveness. The guard removes the entry on every exit path below — clean, error unwind,
    // or the detached child returning. Kept alive to the end of the function.
    let _vm_registration = args.state_dir.as_ref().map(|_| {
        let label = if let Some(p) = &args.primary {
            p.clone()
        } else if !args.image.is_empty() {
            args.image.clone()
        } else if !args.dockerfiles.is_empty() {
            format!("-f {}", args.target.as_deref().unwrap_or("(last stage)"))
        } else {
            "vm".to_string()
        };
        // Capture what the root image was built from, so `vk list --stale` can later tell
        // whether the working tree drifted. Mirror `compose_build_units` (compose --primary)
        // and the `-f` build options exactly, so a recomputed key matches the stamped one.
        // `None` for an image boot (nothing built from a Dockerfile).
        let stale_recipe = dockerfile_ext4.as_ref().and_then(|root| {
            if let Some(idx) = primary_idx {
                if let crate::compose::Source::Build {
                    dockerfiles,
                    context,
                    build_contexts,
                    target,
                    args: unit_args,
                } = &compose_units[idx].source
                {
                    let mut build_args = args.build_args.clone();
                    build_args.extend(unit_args.iter().cloned());
                    return Some(crate::vms::StaleRecipe {
                        dockerfiles: dockerfiles.clone(),
                        contexts: vec![context.clone(); dockerfiles.len()],
                        build_contexts: build_contexts.clone(),
                        build_args,
                        target: target.clone(),
                        root_ext4: root.clone(),
                    });
                }
                None // a compose --primary that is an image: (no build → no drift)
            } else if !args.dockerfiles.is_empty() {
                Some(crate::vms::StaleRecipe {
                    dockerfiles: args.dockerfiles.clone(),
                    contexts: args.contexts.clone(),
                    build_contexts: args.build_contexts.clone(),
                    build_args: args.build_args.clone(),
                    target: args.target.clone(),
                    root_ext4: root.clone(),
                })
            } else {
                None
            }
        });
        let state_dir = registry_key(work);
        // The eager starts above already adopted their built entries; take those addresses
        // from the manager so what is filed names the image each service actually booted.
        if let Some(mgr) = &manager {
            mgr.refresh_service_images(&mut service_entries);
        }
        crate::vms::register(crate::vms::VmEntry {
            // Off the canonical state dir, so a run launched with a relative `--state-dir`
            // still names its recording to a `vk atop` reading from another directory.
            atop_log: atop_log
                .is_some()
                .then(|| state_dir.join("atop").join(vk_core::atop::LOG_NAME)),
            state_dir,
            project_dir: std::env::current_dir().ok(),
            pid: std::process::id(),
            label,
            exec_addr: format!("vsock-auto://{}:{VSOCK_PORT}", vsock.display()),
            ssh_addr: args
                .ssh
                .then(|| format!("vsock-auto://{}:{SSH_VSOCK_PORT}", vsock.display())),
            created_secs: crate::vms::unix_now(),
            stale_recipe,
            services: service_entries,
        })
    });

    // The ProxyCommand splices ssh's stdio onto the guest's vsock ssh port, so
    // the hostname after `user@` is only a known_hosts label. The host key is
    // ephemeral (fresh per boot, reached over a private channel), hence the
    // relaxed checking options.
    if args.ssh {
        // vsock-auto: the ProxyCommand picks the best path itself — the per-port
        // listener when the backend has one, else the CONNECT handshake.
        let target = format!("vsock-auto://{}:{SSH_VSOCK_PORT}", vsock.display());
        let exe = match std::env::current_exe().context("locating the virtkit binary") {
            Ok(exe) => exe,
            Err(e) => {
                teardown_run(
                    &mut ch,
                    &manager,
                    &mut virtiofsds,
                    &mut switch,
                    &mut ssh_forward,
                    &mut host_exec_serve,
                );
                return Err(e);
            }
        };
        println!(
            "virtkit: ssh: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ProxyCommand=\"'{}' connect '{target}'\" {}@vk-run",
            exe.display(),
            args.ssh_user
        );
    }

    // Host side of the SSH-agent forward: the guest dials vsock port SSH_AGENT_VSOCK_PORT,
    // surfaced by cloud-hypervisor as <vsock.sock>_<port>. With --ssh-host a filtering proxy
    // exposes only the chosen keys; a bare --ssh-agent splices the whole agent through.
    let ssh_forward_result = match &ssh {
        Some(s) if s.allow_pub.is_empty() && s.guest_config.is_none() => {
            spawn_ssh_agent_forward(&vsock, &s.upstream, work).map(Some)
        }
        Some(s) => spawn_ssh_agent_proxy(&vsock, &s.upstream, &s.allow_pub, work).map(Some),
        None => Ok(None),
    };
    match ssh_forward_result {
        Ok(fwd) => ssh_forward = fwd,
        Err(e) => {
            teardown_run(
                &mut ch,
                &manager,
                &mut virtiofsds,
                &mut switch,
                &mut ssh_forward,
                &mut host_exec_serve,
            );
            return Err(e);
        }
    }
    let ssh_config = ssh.and_then(|s| s.guest_config);

    // Host side of the host-exec channel: a `vk-agent serve` on the bridged
    // per-port socket the guest's /run/vk/host.sock forwarder dials. cwd is the
    // --workdir (else our own), so a relative `exec --dir` resolves against the
    // shared tree; the wrapper (if any) enforces what may run.
    if args.host_exec {
        match spawn_host_exec_serve(&vsock, agent, args, work) {
            Ok(fwd) => host_exec_serve = Some(fwd),
            Err(e) => {
                teardown_run(
                    &mut ch,
                    &manager,
                    &mut virtiofsds,
                    &mut switch,
                    &mut ssh_forward,
                    &mut host_exec_serve,
                );
                return Err(e);
            }
        }
    }

    let (cmd_entrypoint, fallback_argv) =
        exec_channel_argv(eff_init, &image_entrypoint, primary.as_ref());
    let result = drive(
        &mut ch,
        &addr,
        &console,
        args,
        ssh_config.as_deref(),
        &image_env,
        cmd_entrypoint,
        &image_workdir,
        &fallback_argv,
        &timings,
    )
    .await;
    teardown_run(
        &mut ch,
        &manager,
        &mut virtiofsds,
        &mut switch,
        &mut ssh_forward,
        &mut host_exec_serve,
    );
    // Audit summary (`--audit-egress`): the switch is stopped, so its channel is complete. A
    // no-op when audit was off (no channel written). The guest phase — a `-f` build's own
    // `--build-audit-egress` summary already printed after the build, above.
    if let Some(summary) = crate::egress_report::contacts_summary(
        &work.join(AUDIT_LOG),
        "external domains contacted (audit)",
    ) {
        eprintln!("{summary}");
    }
    if let Some(summary) = crate::egress_report::ip_contacts_summary(
        &work.join(AUDIT_LOG),
        "external IPs/ports contacted (audit)",
    ) {
        eprintln!("{summary}");
    }
    timings.render();
    // Read after teardown: every guest and helper has been waited for, so their CPU is in
    // and the switch has published the last of what it carried.
    if let Some(usage) = meter.read() {
        eprintln!(
            "{}",
            usage.with_network(&work.join(NET_BYTES)).summary("run")
        );
    }
    result
}

/// Tear down every host-side child a run spawned — the VMM, the service manager, the
/// --net switch and virtiofsds, and the ssh-agent / host-exec forwards.
/// Used on both a clean exit and any error after the VMM is live, so a failed run leaks no
/// children (a leaked `vk virtiofsd` would hold this binary's file busy for the next build).
fn teardown_run(
    ch: &mut Child,
    manager: &Option<std::sync::Arc<crate::manager::Manager>>,
    virtiofsds: &mut Vec<Child>,
    switch: &mut Option<Child>,
    ssh_forward: &mut Option<Child>,
    host_exec_serve: &mut Option<Child>,
) {
    for mut f in ssh_forward.take().into_iter().chain(host_exec_serve.take()) {
        let _ = f.kill();
        let _ = f.wait();
    }
    let _ = ch.kill();
    let _ = ch.wait();
    if let Some(mgr) = manager {
        mgr.stop_all();
    }
    for mut child in virtiofsds.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(child) = switch.take() {
        stop_switch(child);
    }
}

/// Stop a run's switch, giving it the moment it needs to publish the bytes it carried
/// ([`NET_BYTES`]) before it goes. SIGKILLed like the rest, a run's last flow — which closes
/// as the guest exits — would be missing from the figure the run reports. Bounded because
/// nothing but a resource line depends on it: a switch that does not go on its own is killed.
fn stop_switch(mut child: Child) {
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    if !crate::vm::wait_child_gone(&mut child, SWITCH_STOP) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Every declared compose unit, materialized and addressed, plus which ones
/// boot eagerly and what the switch must serve for them.
struct PlannedServices {
    /// (provisioned service, runtime dir, compose unit) for the manager — the `--primary`
    /// primary excluded (it boots as the run VM, not as a sibling). The compose unit rides
    /// along so the manager can build a profiled-down service on demand.
    units: Vec<(crate::units::Provisioned, PathBuf, crate::compose::Unit)>,
    /// names to boot eagerly: the profile-enabled set, or the primary's
    /// dependency closure
    start: Vec<String>,
    /// per-unit switch sockets (up or down — an on-demand start dials a
    /// listening LAN), each paired with the sibling's assigned address so the
    /// switch binds the socket to it (a sibling can only source its own IP)
    listen: Vec<(PathBuf, std::net::Ipv4Addr)>,
    /// alias -> ip for the gateway resolver
    hosts: Vec<(String, String)>,
    /// per-sibling DHCP reservations (mac, ip): a sibling's deterministic MAC ->
    /// its run-assigned IP, so an image-init sibling that DHCPs eth0 lands on the
    /// address the resolver advertises for its name
    reservations: Vec<(String, String)>,
}

/// The units in `order` a `--compose` selection materializes up front: the primary plus the
/// eager start set (`on`), and every `image:` service. Used by `vk build --compose` (which
/// exports each selected unit, image services included). The `vk run` path
/// ([`build_compose_images`]) reuses this but skips non-primary `image:` services — those
/// resolve through the shared image cache (`image::resolve_ref`) rather than a build.
fn eager_build_selection(
    units: &[crate::compose::Unit],
    order: &[usize],
    primary_idx: Option<usize>,
    on: &[bool],
) -> Vec<usize> {
    order
        .iter()
        .copied()
        .filter(|&i| {
            Some(i) == primary_idx
                || on[i]
                || matches!(units[i].source, crate::compose::Source::Image(_))
        })
        .collect()
}

/// Resolve a `--primary` service name to its index in `units`, erroring with the list of
/// declared services when it isn't found — so the build and run paths report the same message.
fn resolve_primary(units: &[crate::compose::Unit], name: &str) -> Result<usize> {
    units.iter().position(|u| u.name == name).ok_or_else(|| {
        anyhow::anyhow!(
            "--primary {name:?}: no such compose service (declared: {})",
            units
                .iter()
                .map(|u| u.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// Layer the CLI per-service sizing overrides (`--service-cpus`/`--service-mem
/// NAME=VALUE`) over the loaded units' own `x-virtkit` sizing. A name matching no
/// declared service is an error naming the declared set, like `--primary`.
fn apply_service_sizes(
    units: &mut [crate::compose::Unit],
    cpus: &[(String, u32)],
    mem: &[(String, String)],
) -> Result<()> {
    let find = |units: &[crate::compose::Unit], flag: &str, name: &str| -> Result<usize> {
        units.iter().position(|u| u.name == name).with_context(|| {
            format!(
                "{flag} {name:?}: no such compose service (declared: {})",
                units
                    .iter()
                    .map(|u| u.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    };
    for (name, n) in cpus {
        let i = find(units, "--service-cpus", name)?;
        units[i].cpus = Some(*n);
    }
    for (name, m) in mem {
        let i = find(units, "--service-mem", name)?;
        units[i].mem = Some(m.clone());
    }
    Ok(())
}

/// The compose service indices `vk build --compose` builds: exactly the set `vk run --compose`
/// would boot for the same `--profile` / `--primary` selection — the enabled set (profiled-down
/// services excluded) or, with `--primary`, that service plus its dependency closure — and every
/// `image:` service. Computed the same way as [`build_compose_images`], so a `--compose` build
/// warms precisely what a boot needs and leaves a profiled-down `build:` service for its first
/// on-demand `vk service up`. Name a service's profile with `--profile` to build it anyway.
pub(crate) fn compose_build_selection(
    units: &[crate::compose::Unit],
    profiles: &[String],
    primary: Option<&str>,
) -> Result<Vec<usize>> {
    let primary_idx = match primary {
        Some(name) => Some(resolve_primary(units, name)?),
        None => None,
    };
    let order = crate::compose::boot_order(units)?;
    let on = match primary_idx {
        Some(idx) => crate::compose::dependency_closure(units, idx),
        None => crate::compose::enabled(units, profiles),
    };
    Ok(eager_build_selection(units, &order, primary_idx, &on))
}

/// Materialize the `--primary` primary up front, exported to the run's bootable `root.ext4`
/// (it boots as the run VM, not a sibling). Sibling services are NOT built here: an `image:`
/// sibling resolves through the shared image cache (`image::resolve_ref`) in `plan_services`,
/// and a `build:` sibling materializes into the shared build tier on its first start (the
/// manager, via `ensure_unit_build_sync`) — so both dedup across runs and runners. Returns
/// the primary's [`Built`](crate::build::Built) config keyed by its name (empty for a
/// compose-up run, which has no primary).
fn build_compose_images(
    args: &RunArgs,
    work: &Path,
    kernel: &Path,
    agent: &Path,
    units: &[crate::compose::Unit],
    primary_idx: Option<usize>,
) -> Result<std::collections::HashMap<String, crate::build::Built>> {
    let Some(primary_idx) = primary_idx else {
        return Ok(std::collections::HashMap::new());
    };
    // Only the primary is selected; its target exports to root.ext4.
    let out_of = |_unit: &crate::compose::Unit| -> Option<PathBuf> { Some(work.join("root.ext4")) };
    let units_to_build = compose_build_units(&args.build_args, units, &[primary_idx], out_of);
    let opts = service_build_options(args, kernel, agent);
    crate::build::build_units(units_to_build, &opts)
}

/// Provision EVERY declared unit — address it, give it a runtime dir, resolve its clean
/// image, and merge its config — so the manager can start any of them later; only `start`
/// boots eagerly. An `image:` sibling resolves through the shared image cache
/// (`image::resolve_ref`, the same digest-keyed cache the CI job + services use) and carries
/// its real config. A `build:` sibling addresses its shared build-tier ext4 (a pure function
/// of the stage fingerprint) but is not built yet — it gets the compose overrides alone as a
/// placeholder until the manager builds it on demand at first start and adopts the entry it
/// built, with that image's config.
fn plan_services(
    args: &RunArgs,
    cfg: &crate::config::Config,
    state_dir: &Path,
    work: &Path,
    units: &[crate::compose::Unit],
    primary_idx: Option<usize>,
) -> Result<PlannedServices> {
    let mut planned = PlannedServices {
        units: Vec::new(),
        start: Vec::new(),
        listen: Vec::new(),
        hosts: Vec::new(),
        reservations: Vec::new(),
    };
    if args.compose.is_none() {
        return Ok(planned);
    }
    let order = crate::compose::boot_order(units)?;
    // A --primary primary starts only its dependencies (compose-run semantics);
    // otherwise the profile-enabled set boots.
    let on = match primary_idx {
        Some(idx) => crate::compose::dependency_closure(units, idx),
        None => crate::compose::enabled(units, &args.profiles),
    };
    let (gw, prefix, _) = crate::net::switch_addrs(RUN_SUBNET)?;
    // Site each sibling (its runtime dir + address slot), excluding the primary (it boots as
    // the run VM, not a sibling). Kept in boot order so the eager `start` list and slot/IP
    // assignment stay stable.
    struct Sited {
        unit: usize,
        dir: PathBuf,
        slot: u32,
    }
    let mut sited = Vec::new();
    let mut slot = 0u32;
    for &i in &order {
        if Some(i) == primary_idx {
            continue;
        }
        let unit = &units[i];
        let dir = work.join(format!("svc-{}", unit.name));
        // The switch binds each service's vsock socket under this dir at startup, and the
        // boot writes the overlay/console here — so it must exist before either runs.
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        sited.push(Sited { unit: i, dir, slot });
        slot += 1;
    }

    // Resolve + address each service through the shared provisioning path (the same one the
    // CI executor uses), then derive the switch's per-unit listen socket, resolver aliases and
    // DHCP reservation from it.
    for s in sited {
        let unit = &units[s.unit];
        let prov =
            crate::units::provision(cfg, state_dir, &args.build_args, unit, gw, prefix, s.slot)?;
        let ip = prov.addr.to_string();
        planned.listen.push((
            s.dir.join(format!("vsock.sock_{NET_VSOCK_PORT}")),
            prov.addr,
        ));
        planned
            .hosts
            .push((unit.name.to_ascii_lowercase(), ip.clone()));
        if unit.hostname != unit.name {
            planned
                .hosts
                .push((unit.hostname.to_ascii_lowercase(), ip.clone()));
        }
        // Reserve this sibling's deterministic MAC (== the one boot_unit puts on the
        // cmdline) to its IP, so a DHCPing image-init sibling gets its advertised IP.
        planned
            .reservations
            .push((crate::units::mac_for_ip(prov.addr), ip.clone()));
        let starts = on[s.unit];
        let name = prov.name.clone();
        planned.units.push((prov, s.dir, unit.clone()));
        if starts {
            planned.start.push(name);
        }
    }
    Ok(planned)
}

/// `vk run --compose` with no primary — compose up: boot the enabled services
/// on the run LAN and hold until ctrl-c; everything dies with this process.
async fn compose_up(
    args: &RunArgs,
    cfg: &crate::config::Config,
    state_dir: &Path,
    work: &Path,
    agent: &Path,
    kernel: &Path,
) -> Result<()> {
    let compose = args
        .compose
        .as_ref()
        .expect("compose_up requires --compose");
    let mut units = crate::compose::load(compose)?;
    if units.is_empty() {
        bail!("{} declares no services", compose.display());
    }
    apply_service_sizes(&mut units, &args.service_cpus, &args.service_mem)?;
    // What the fleet costs the host while it is up (see `usage`). Opened before
    // `plan_services`, which builds nothing but does resolve and materialize every `image:`
    // service — work that falls inside the window in the run above, so metering it here too
    // keeps the two call sites reporting the same span. As there, a `build:` service the
    // shared tier is missing builds when it is started, inside this window, which withholds
    // both lines rather than crossing them.
    let meter = crate::usage::Meter::start();

    // compose-up has no primary — every unit is a sibling, so there is nothing to build up
    // front here (siblings resolve/build via plan_services + the manager).
    let planned = plan_services(args, cfg, state_dir, work, &units, None)?;

    // The switch binds every unit's socket; no VM ever dials the base socket
    // (there is no primary), it is just the switch's canonical listen path.
    let vsock = work.join("vsock.sock");
    let (mut switch, _frag) = spawn_vm_switch(
        &vsock,
        work,
        NET_VSOCK_PORT,
        &[],
        &[],
        &planned.listen,
        &planned.hosts,
        &planned.reservations,
        None,
        args.audit_egress.then(|| work.join(AUDIT_LOG)),
        Some(work.join(NET_BYTES)),
        false,
    )
    .await?;

    let (gw, prefix, _) = crate::net::switch_addrs(RUN_SUBNET)?;
    let mgr = std::sync::Arc::new(crate::manager::Manager::new(
        kernel.to_path_buf(),
        args.cloud_hypervisor.clone(),
        NET_VSOCK_PORT,
        gw,
        agent.to_path_buf(),
        manager_build_opts(args, kernel, agent),
        crate::manager::ManagerDirs {
            cache: state_dir.to_path_buf(),
            // A services-only run files no registry entry, so there is none to correct.
            run: None,
        },
        cfg.image_cache_idle(),
        planned.units,
    ));
    for name in &planned.start {
        let reply = mgr.start(name);
        if !reply.ok {
            mgr.stop_all();
            let _ = switch.kill();
            let _ = switch.wait();
            bail!("booting service {name}: {}", reply.message);
        }
        println!("virtkit: service {name}: {}", reply.message);
    }
    println!(
        "virtkit: compose up on {gw}/{prefix}; {} of {} service(s) started — ctrl-c stops everything",
        planned.start.len(),
        mgr.declared(),
    );
    // Every service booted; for a `--detach` run, daemonize now so the terminal is freed
    // while the services keep running (a no-op unless this is the forked child).
    if args.detach {
        crate::detach::signal_ready(args.detach_log.as_deref());
    }
    tokio::signal::ctrl_c().await.ok();
    println!("virtkit: stopping ...");
    mgr.stop_all();
    stop_switch(switch);
    if let Some(summary) = crate::egress_report::contacts_summary(
        &work.join(AUDIT_LOG),
        "external domains contacted (audit)",
    ) {
        eprintln!("{summary}");
    }
    if let Some(summary) = crate::egress_report::ip_contacts_summary(
        &work.join(AUDIT_LOG),
        "external IPs/ports contacted (audit)",
    ) {
        eprintln!("{summary}");
    }
    // Read after stop_all: every service VM has been waited for, so their CPU is in.
    if let Some(usage) = meter.read() {
        eprintln!(
            "{}",
            usage.with_network(&work.join(NET_BYTES)).summary("run")
        );
    }
    Ok(())
}

/// The builder wiring the service manager needs to build a profiled-down `build:` service
/// on demand at its first start — the same embedded kernel/agent, cache and build args the
/// up-front `build_compose_images` used, so an on-demand build restores from the same cache.
fn manager_build_opts(args: &RunArgs, kernel: &Path, agent: &Path) -> crate::units::BuildOpts {
    crate::units::BuildOpts {
        build_args: args.build_args.clone(),
        kernel: kernel.to_path_buf(),
        cloud_hypervisor: args.cloud_hypervisor.clone(),
        agent: agent.to_path_buf(),
        cache_registry: args.cache_registry.clone(),
        cache_insecure: args.cache_insecure,
        cache_auth: Default::default(),
        // Dev `vk run --compose` service builds share the run's `--build-net` / build-audit.
        net: args.build_net.clone(),
        audit: args.build_audit_egress,
    }
}

/// The build options common to every compose service build (the embedded kernel/agent, the
/// instruction cache, egress policy). Per-service inputs/target/args/out are filled in by
/// the caller; [`build_units`](crate::build::build_units) reads them from each `BuildUnit`
/// instead, so the `out`/`dockerfiles`/`build_args` left here are unused on that path.
pub(crate) fn service_build_options(
    args: &RunArgs,
    kernel: &Path,
    agent: &Path,
) -> crate::build::Options {
    crate::build::Options {
        dockerfiles: Vec::new(),
        target: None,
        contexts: Vec::new(),
        build_contexts: Vec::new(),
        out: None,
        out_disk: None,
        print_plan: false,
        cloud_hypervisor: Some(args.cloud_hypervisor.clone()),
        kernel: Some(kernel.to_path_buf()),
        agent: Some(agent.to_path_buf()),
        cache_registry: args.cache_registry.clone(),
        cache_insecure: args.cache_insecure,
        cache_auth: Default::default(),
        build_cache: crate::build::BuildCache::default(),
        journal: false,
        tmp_tmpfs: false,
        build_args: args.build_args.clone(),
        net: args.build_net.clone(),
        audit: args.build_audit_egress,
        require_cached: args.require_cached,
        build_jobs: None,
        debug: false,
        progress_sink: None,
    }
}

/// Map the selected compose services to [`BuildUnit`](crate::build::BuildUnit)s for a
/// unified build. `build:` services with identical inputs (Dockerfile(s), contexts, and
/// resolved build args) merge into one unit — one plan, one target per service — so their
/// common stages build once; services with differing inputs, and each `image:` service,
/// become their own unit. `out_of` gives each service its export path (`None` = warm the
/// cache only). Build args are the global `--build-arg`s with the service's own `build.args`
/// layered on top (a service arg wins on a duplicate key). Each target is labelled with its
/// service name, so the returned [`Built`] map is keyed by service name.
pub(crate) fn compose_build_units(
    global_build_args: &[(String, String)],
    units: &[crate::compose::Unit],
    selected: &[usize],
    out_of: impl Fn(&crate::compose::Unit) -> Option<PathBuf>,
) -> Vec<crate::build::BuildUnit> {
    // A build group's identity: (dockerfiles, contexts, named contexts, resolved build args).
    // Services with an equal signature share one plan, so they merge into one multi-target unit.
    type BuildSig = (
        Vec<PathBuf>,
        Vec<PathBuf>,
        Vec<(String, PathBuf)>,
        Vec<(String, String)>,
    );
    let mut result: Vec<crate::build::BuildUnit> = Vec::new();
    let mut groups: Vec<(BuildSig, usize)> = Vec::new(); // signature -> index into `result`
    for &i in selected {
        let unit = &units[i];
        let target = |selector: Option<String>| crate::build::TargetSpec {
            label: unit.name.clone(),
            selector,
            out: out_of(unit),
        };
        match &unit.source {
            crate::compose::Source::Build {
                dockerfiles,
                context,
                build_contexts,
                target: stage,
                args: unit_args,
            } => {
                // compose semantics: one context for all the service's files.
                let contexts = vec![context.clone(); dockerfiles.len()];
                let mut build_args = global_build_args.to_vec();
                build_args.extend(unit_args.iter().cloned());
                // The named contexts are part of the identity: two services differing only in
                // their `additional_contexts` must not be merged into one unit.
                let sig = (
                    dockerfiles.clone(),
                    contexts.clone(),
                    build_contexts.clone(),
                    build_args.clone(),
                );
                // Order-sensitive on build_args and build_contexts: two services declaring the
                // same ones in a different order won't merge, though they key identically (the
                // plan holds the contexts in a map). A missed optimization, not a bug.
                if let Some((_, ri)) = groups.iter().find(|(s, _)| *s == sig) {
                    result[*ri].targets.push(target(stage.clone()));
                } else {
                    groups.push((sig, result.len()));
                    result.push(crate::build::BuildUnit {
                        label: unit.name.clone(),
                        input: crate::build::UnitInput::Build {
                            dockerfiles: dockerfiles.clone(),
                            contexts,
                            build_contexts: build_contexts.clone(),
                        },
                        build_args,
                        targets: vec![target(stage.clone())],
                    });
                }
            }
            crate::compose::Source::Image(image) => result.push(crate::build::BuildUnit {
                label: unit.name.clone(),
                input: crate::build::UnitInput::Image(image.clone()),
                build_args: global_build_args.to_vec(),
                targets: vec![target(None)],
            }),
        }
    }
    result
}

/// Spawn the host side of the SSH-agent forward: `vk forward` binds the VMM's per-port
/// vsock socket (`<vsock.sock>_<port>`) and splices every guest connection to the host's
/// `$SSH_AUTH_SOCK`. Long-lived for the VM's lifetime; the caller kills it on teardown.
fn spawn_ssh_agent_forward(vsock: &Path, host_sock: &OsStr, work: &Path) -> Result<Child> {
    let mut listen = vsock.to_path_buf().into_os_string();
    listen.push(format!("_{SSH_AGENT_VSOCK_PORT}"));
    let log = std::fs::File::create(work.join("ssh-agent-forward.log"))
        .context("creating the ssh-agent forward log")?;
    let mut cmd = Command::new(crate::spawn::self_exe());
    cmd.arg("forward")
        .arg("--listen")
        .arg(&listen)
        .arg("--to")
        .arg(host_sock)
        .stdout(log.try_clone()?)
        .stderr(log);
    // self-reap if virtkit dies before teardown (spawn_tied)
    crate::spawn::spawn_tied(cmd).context("spawning the ssh-agent forward")
}

/// Spawn the host side of the `--host-exec` channel: a `vk-agent serve` listening on
/// the VMM's bridged per-port socket (`<vsock.sock>_<HOST_EXEC_PORT>`), which the
/// guest's `/run/vk/host.sock` forwarder dials. The serve runs with the `--workdir`
/// (else our own cwd) as its working directory, so a guest `exec --dir .` resolves
/// against the shared tree; `--host-exec-wrapper` forces every command through an
/// allowlist program. Without a wrapper the guest can run any host command as the
/// host user — the opt-in contract of `--host-exec`. The serve inherits virtkit's
/// host environment so the commands it runs (docker, a browser, …) have a working
/// host PATH/HOME; the wrapper's own allowlist gates the *client* env on top.
/// Long-lived for the VM's lifetime; the caller kills it on teardown, and
/// `spawn_tied` reaps it if virtkit dies first.
fn spawn_host_exec_serve(vsock: &Path, agent: &Path, args: &RunArgs, work: &Path) -> Result<Child> {
    let listen = crate::vmm::hybrid_socket(vsock, HOST_EXEC_PORT);
    let log = std::fs::File::create(work.join("host-exec-serve.log"))
        .context("creating the host-exec serve log")?;
    let mut cmd = Command::new(agent);
    cmd.args(host_exec_serve_args(
        &listen,
        args.host_exec_wrapper.as_deref(),
        &args.host_exec_env,
    ));
    if let Some(dir) = &args.workdir {
        cmd.current_dir(dir);
    }
    cmd.stdout(log.try_clone()?).stderr(log);
    crate::spawn::spawn_tied(cmd).context("spawning the host-exec serve")
}

/// Argv for the host-side `--host-exec` serve: `-s <listen> serve`, plus the
/// allowlist wrapper (`--exec-wrapper`) and its client-env globs
/// (`--exec-wrapper-env`) when a wrapper was given. Without a wrapper the serve
/// runs commands unrestricted — the opt-in contract of `--host-exec`.
fn host_exec_serve_args(
    listen: &Path,
    wrapper: Option<&Path>,
    env_globs: &[String],
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["-s".into(), listen.into(), "serve".into()];
    if let Some(wrapper) = wrapper {
        argv.push("--exec-wrapper".into());
        argv.push(wrapper.into());
        for glob in env_globs {
            argv.push("--exec-wrapper-env".into());
            argv.push(glob.into());
        }
    }
    argv
}

/// How `--ssh-agent`/`--ssh-host` resolve for a launch: the host agent socket to expose,
/// the public keys it may offer (empty = the whole agent), and the `~/.ssh/config` stanzas
/// to inject into the guest (only for `--ssh-host`).
struct SshAgentSetup {
    upstream: std::ffi::OsString,
    allow_pub: Vec<PathBuf>,
    guest_config: Option<String>,
}

/// Resolve the SSH-agent forwarding for this launch. `--ssh-host` implies forwarding and
/// restricts it to the named `~/.ssh/config` aliases (their keys + injected config); a bare
/// `--ssh-agent` forwards the whole agent. Returns `None` if forwarding is off or the host
/// has no `$SSH_AUTH_SOCK`.
/// Encode OpenSSH public keys for the kernel cmdline: `type:base64` entries
/// joined by commas (the cmdline is whitespace-split, so spaces and the key
/// comment are dropped); the agent decodes each back to `type base64` and hands
/// it to ssh-serve as an authorized key.
fn encode_ssh_keys(keys: &[String]) -> Result<String> {
    let mut encoded = Vec::new();
    for key in keys {
        let mut parts = key.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some(key_type), Some(base64)) => encoded.push(format!("{key_type}:{base64}")),
            _ => {
                bail!("--ssh-key {key:?} is not an OpenSSH public key (expected `type base64 ...`)")
            }
        }
    }
    Ok(encoded.join(","))
}

/// A login name safe to splice into the whitespace-split kernel cmdline (see
/// `read_cmdline` in vk-agent): non-empty and restricted to the portable POSIX
/// username charset, so whitespace or `=` can't corrupt `VIRTKIT_SSH_USER=` or
/// the tokens around it.
pub fn parse_ssh_user(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("must not be empty".into());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(format!(
            "{s:?} is not a valid login name (allowed: letters, digits, `_`, `-`, `.`)"
        ));
    }
    Ok(s.to_string())
}

/// The default `--ssh` identities: the standard public keys under `~/.ssh`.
fn default_ssh_pubkeys() -> Result<Vec<String>> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("--ssh with no --ssh-key needs $HOME to find ~/.ssh")?;
    let keys = ssh_pubkeys_in(&home.join(".ssh"));
    if keys.is_empty() {
        bail!(
            "--ssh: no public key under {} (id_ed25519/id_ecdsa/id_rsa) — pass --ssh-key",
            home.join(".ssh").display()
        );
    }
    Ok(keys)
}

// Each standard identity file holds a single key; `encode_ssh_keys` keys off the
// first `type base64` pair, so only the first key of a file (were it multi-line) is
// authorized — a non-issue for the id_*.pub these read.
fn ssh_pubkeys_in(ssh_dir: &Path) -> Vec<String> {
    ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"]
        .iter()
        .filter_map(|name| std::fs::read_to_string(ssh_dir.join(name)).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn ssh_agent_setup(args: &RunArgs) -> Option<SshAgentSetup> {
    if !args.ssh_agent && args.ssh_hosts.is_empty() {
        return None;
    }
    let Some(upstream) = std::env::var_os("SSH_AUTH_SOCK") else {
        eprintln!("virtkit: SSH agent requested but SSH_AUTH_SOCK is unset — not forwarding");
        return None;
    };
    if args.ssh_hosts.is_empty() {
        return Some(SshAgentSetup {
            upstream,
            allow_pub: Vec::new(),
            guest_config: None,
        });
    }
    // --ssh-host: resolve the chosen aliases, collect their keys' .pub files (the agent
    // filter allowlist) and a minimal guest config so `ssh <alias>` resolves in the VM.
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let cfg = std::fs::read_to_string(home.join(".ssh/config")).unwrap_or_default();
    let entries = crate::sshconf::resolve(&cfg, &args.ssh_hosts, &home);
    for want in &args.ssh_hosts {
        if !entries.iter().any(|e| &e.alias == want) {
            eprintln!("virtkit: --ssh-host {want}: not found in ~/.ssh/config — skipped");
        }
    }
    let mut allow_pub = Vec::new();
    let mut guest_config = String::new();
    for e in &entries {
        guest_config.push_str(&e.stanza());
        guest_config.push('\n');
        if e.identity_files.is_empty() {
            eprintln!(
                "virtkit: --ssh-host {}: no IdentityFile — its key can't be exposed",
                e.alias
            );
        }
        for id in &e.identity_files {
            let mut p = id.clone().into_os_string();
            p.push(".pub");
            allow_pub.push(PathBuf::from(p));
        }
    }
    Some(SshAgentSetup {
        upstream,
        allow_pub,
        guest_config: Some(guest_config),
    })
}

/// Spawn the host side of a key-filtered SSH-agent forward: `vk ssh-agent-proxy` binds
/// the VMM's per-port vsock socket and relays to `$SSH_AUTH_SOCK`, exposing only `allow_pub`.
fn spawn_ssh_agent_proxy(
    vsock: &Path,
    upstream: &OsStr,
    allow_pub: &[PathBuf],
    work: &Path,
) -> Result<Child> {
    let mut listen = vsock.to_path_buf().into_os_string();
    listen.push(format!("_{SSH_AGENT_VSOCK_PORT}"));
    let log = std::fs::File::create(work.join("ssh-agent-forward.log"))
        .context("creating the ssh-agent forward log")?;
    let mut cmd = Command::new(crate::spawn::self_exe());
    cmd.arg("ssh-agent-proxy")
        .arg("--listen")
        .arg(&listen)
        .arg("--upstream")
        .arg(upstream);
    for p in allow_pub {
        cmd.arg("--allow").arg(p);
    }
    // self-reap if virtkit dies before teardown (spawn_tied)
    cmd.stdout(log.try_clone()?).stderr(log);
    crate::spawn::spawn_tied(cmd).context("spawning the ssh-agent proxy")
}

/// Wait for the in-guest virtkit-agent, run the command, relay its output. `ssh_config`, if
/// set, is written to the guest's `~/.ssh/config` once it is ready (the `--ssh-host` stanzas).
/// Single-quote a value for a `/bin/sh` `export` (wrap in `'…'`, escaping embedded `'`).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The guest script for the trailing command. Empty: a boot-info probe. One
/// argument: a shell one-liner, taken verbatim (`-- 'echo a | nc b 1234'`).
/// Several: an argv — each word quoted so its boundaries survive the guest's
/// script shell, like `docker run`: `-- sh -c 'complex | script'` reaches the
/// guest exactly as typed.
fn user_script(command: &[String]) -> String {
    match command {
        [] => {
            "echo PID1=$(cat /proc/1/comm); id; uname -a; cat /etc/os-release | head -1".to_string()
        }
        [script] => script.clone(),
        argv => argv
            .iter()
            .map(|a| sh_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// What the exec channel starts from: the entrypoint a trailing command is wrapped in, and
/// the argv a run with no trailing command gets. Normally the image's entrypoint and — with
/// a `--primary` primary — that service's own entrypoint+cmd, `docker compose run <svc>`
/// semantics. Both are empty under `--init entrypoint`, where that argv is PID 1 already:
/// running it again would repeat the machine preparation inside the machine it just
/// prepared, so a trailing command runs on its own and a run without one gets the boot-info
/// probe, which is what there is to look at.
fn exec_channel_argv<'a>(
    init: InitSource,
    image_entrypoint: &'a [String],
    primary: Option<&vk_core::runcfg::RunConfig>,
) -> (&'a [String], Vec<String>) {
    if init == InitSource::Entrypoint {
        return (&[], Vec::new());
    }
    (
        image_entrypoint,
        primary.map(|c| c.argv()).unwrap_or_default(),
    )
}

/// The shell body a run executes in the guest, `docker run`-style. With no trailing
/// command the fallback runs (a `--primary` service's entrypoint+cmd, else the boot-info
/// probe). A trailing command has the image's entrypoint prepended and is quoted as an
/// argv; with no entrypoint a single word stays a shell one-liner (the CLI's documented
/// shorthand). It runs in the effective cwd: the `--workdir` share (WORKDIR_MOUNT, so its
/// outputs land back on the host), else the image's WORKDIR — `/` is the default either
/// way, so no `cd` is emitted for it.
fn guest_command_body(
    command: &[String],
    image_entrypoint: &[String],
    image_workdir: &str,
    workdir_share: bool,
    fallback_argv: &[String],
) -> String {
    let script = if command.is_empty() {
        user_script(fallback_argv)
    } else if image_entrypoint.is_empty() {
        user_script(command)
    } else {
        image_entrypoint
            .iter()
            .chain(command)
            .map(|a| sh_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let cwd = if workdir_share {
        Some(WORKDIR_MOUNT)
    } else if !image_workdir.is_empty() && image_workdir != "/" {
        Some(image_workdir)
    } else {
        None
    };
    match cwd {
        Some(dir) => format!("cd {} && {script}", sh_quote(dir)),
        None => script,
    }
}

/// How often an inactivity-managed detached run re-checks that its guest is still there:
/// the guest watchdog's own resolution, capped at ten seconds so a self-poweroff is noticed
/// promptly. A zero timeout arms no watchdog and so has no poweroff to catch — it polls
/// slowly, just often enough to notice a guest that died some other way.
fn status_poll_period(inactivity_timeout_secs: Option<u64>) -> Duration {
    Duration::from_secs(
        inactivity_timeout_secs
            .filter(|secs| *secs > 0)
            .map_or(60, |secs| secs.min(10)),
    )
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    ch: &mut Child,
    addr: &SocketAddr,
    console: &Path,
    args: &RunArgs,
    ssh_config: Option<&str>,
    image_env: &[(String, String)],
    image_entrypoint: &[String],
    image_workdir: &str,
    fallback_argv: &[String],
    timings: &Timings,
) -> Result<()> {
    let t_boot = Instant::now();
    let deadline = t_boot + Duration::from_secs(args.boot_timeout_secs);
    loop {
        if let Some(status) = ch.try_wait()? {
            bail!("{}", boot_failure(console, status));
        }
        if vk_core::status::get_status(addr).await.is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "VM not ready after {}s\n{}",
                args.boot_timeout_secs,
                tail(console, 20)
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    timings.record(Phase::Boot, "", t_boot.elapsed());
    if let Some(cfg) = ssh_config {
        write_guest_ssh_config(addr, cfg).await?;
    }
    // The guest has answered its status probe (booted, agent serving) and its ssh config is
    // in place. For a `--detach` run this is the moment to daemonize: redirect output to the
    // log and wake the foreground parent, which returns to the shell while this process holds
    // the VM below. A boot failure above bails before here, so it surfaces in the foreground.
    // A no-op unless this process is the forked `--detach` child.
    if args.detach {
        crate::detach::signal_ready(args.detach_log.as_deref());
    }
    if args.shell {
        return run_shell(addr).await;
    }
    let body = guest_command_body(
        &args.command,
        image_entrypoint,
        image_workdir,
        args.workdir.is_some(),
        fallback_argv,
    );
    // Apply the built image's environment first (PATH etc.), so the command runs like
    // `docker run` — the base image's PATH puts toolchains in scope. The command's own
    // exports (if any) come after and win.
    let mut script = String::new();
    for (k, v) in image_env {
        // Only emit valid shell identifiers: a crafted image `Config.Env` key with shell
        // metacharacters would otherwise inject into this `sh -c` body (the value is already
        // quoted by sh_quote; the name is not).
        if k.is_empty()
            || !k
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        {
            eprintln!("virtkit: skipping image env var with non-identifier name {k:?}");
            continue;
        }
        script.push_str(&format!("export {k}={}; ", sh_quote(v)));
    }
    script.push_str(&body);
    let t_exec = Instant::now();
    // `-t`: run the command interactively under a remote pty wired to the local terminal
    // (`docker run -t`); otherwise relay its stdout/stderr straight through.
    let result = if args.tty {
        run_tty(addr, "sh", vec!["-c".into(), script])
            .await
            .context("running the command in the guest (tty)")?
    } else {
        let command = vec!["sh".into(), "-c".into(), script];
        crate::executor::exec_script(
            addr,
            &command,
            Vec::new(),
            None,
            &crate::executor::OutputSink::Inherit,
            None,
        )
        .await
        .context("running the command in the guest")?
    };
    timings.record(Phase::Exec, "", t_exec.elapsed());
    match result.code {
        Some(0) | None => {}
        Some(c) => bail!("guest command exited {c}"),
    }
    // Ordinarily the startup command owns the run lifetime. An inactivity-managed detached
    // run instead leaves the exec server available for later `vk exec` calls. Its status
    // requests do not count as activity, so they can also detect the watchdog exiting and
    // route through the normal host teardown. The VMM usually exits on guest poweroff, but
    // not every libkrun version reports it promptly; accepting either signal avoids a leak.
    if args.inactivity_timeout_secs.is_some() {
        // Only the rare VMM that misses its guest's poweroff needs these probes at all —
        // `try_wait` above catches the ordinary case within one poll — so they can afford to
        // be slow, and a starved guest must not be mistaken for one that is gone and torn
        // down under whatever `vk exec` is running. Probe failures do not decorrelate (the
        // load causing them is still there a poll later), so insist on a long streak.
        const PROBE_FAILURES_BEFORE_GONE: u32 = 6;
        let status_poll = status_poll_period(args.inactivity_timeout_secs);
        let mut failures = 0;
        while ch.try_wait()?.is_none() {
            if vk_core::status::get_status(addr).await.is_err() {
                failures += 1;
                if failures >= PROBE_FAILURES_BEFORE_GONE {
                    break;
                }
            } else {
                failures = 0;
            }
            tokio::time::sleep(status_poll).await;
        }
    }
    Ok(())
}

/// Write the `--ssh-host` stanzas into the guest's `~/.ssh/config` (0600, dir 0700) so
/// `ssh <alias>` resolves there. The config is piped on the command's stdin into `cat`.
async fn write_guest_ssh_config(addr: &SocketAddr, config: &str) -> Result<()> {
    let cmd = vec![
        "sh".to_string(),
        "-c".into(),
        "umask 077 && mkdir -p ~/.ssh && cat > ~/.ssh/config".into(),
    ];
    let r = crate::executor::exec_script(
        addr,
        &cmd,
        config.as_bytes().to_vec(),
        None,
        &crate::executor::OutputSink::Inherit,
        None,
    )
    .await
    .context("writing ~/.ssh/config in the guest")?;
    match r.code {
        Some(0) | None => Ok(()),
        Some(c) => bail!("writing ~/.ssh/config in the guest failed (exit {c})"),
    }
}

/// Run `name args…` interactively in the guest over a remote PTY wired to the local
/// terminal (raw mode), sized to it. Returns when the process exits, with its result.
async fn run_tty(
    addr: &SocketAddr,
    name: &str,
    args: Vec<String>,
) -> Result<vk_core::messages::CmdResult> {
    use vk_core::messages::{CmdExec, RunMode, Tty};
    let (rows, cols) = vk_core::pty::get_winsize(0).unwrap_or((24, 80));
    let (stream, sink) = vk_core::net::connect(addr)
        .await
        .context("connecting to the VM's vk-agent")?;
    let exec = CmdExec {
        name: name.into(),
        args,
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        dir: None,
        tty: Some(Tty {
            term: std::env::var("TERM").ok(),
            rows,
            cols,
        }),
        user: None,
    };
    vk_core::exec::client::client_run_tty(stream, sink, exec).await
}

/// Attach an interactive shell to the guest. Returns when the shell exits, whatever its
/// status — a shell that quits non-zero is not a launch failure.
async fn run_shell(addr: &SocketAddr) -> Result<()> {
    run_tty(addr, "sh", vec!["-i".into()])
        .await
        .context("interactive guest shell")?;
    Ok(())
}

pub(crate) fn spawn_vmm(vmm: &dyn Vmm, spec: &crate::vmm::VmSpec) -> Result<Child> {
    // Every boot funnels through here, so this is where a nesting request meets the host,
    // whichever spec asked and whichever backend serves it: libkrun would mask VMX/SVM
    // back out and cloud-hypervisor cannot mask it at all, so either would otherwise hand
    // the guest a /dev/kvm that never appears. `vk run` refuses earlier, before the pull,
    // for its own flag.
    if spec.nested && !crate::vmm::host_nesting_enabled() {
        bail!(
            "nested virtualization is not enabled on the host \
             (kvm_intel.nested / kvm_amd.nested)"
        );
    }
    let log = std::fs::File::create(spec.serial_log.with_extension("vmm.log"))?;
    let mut cmd = vmm.command(spec);
    cmd.stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // An embedded kernel and unlinked boot media (spec.pass_fds) are CLOEXEC fds
    // addressed as /proc/self/fd/<n> (so idle helpers never inherit them). Hand them to
    // the VMM alone by clearing CLOEXEC on those fds in the forked child, so they
    // survive exec — same numbers — and the VMM can open the paths.
    let mut fds = spec.pass_fds.clone();
    if let Some(fd) = spec
        .kernel
        .to_str()
        .and_then(|s| s.strip_prefix("/proc/self/fd/"))
        .and_then(|n| n.parse::<std::os::unix::io::RawFd>().ok())
    {
        fds.push(fd);
    }
    if !fds.is_empty() {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec runs in the forked child before exec; fcntl(F_SETFD) is
        // async-signal-safe. F_SETFD 0 clears FD_CLOEXEC (the only fd flag).
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &fds {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    // Self-reap the VM if virtkit dies before teardown — a leaked VMM is a whole
    // running guest, not just an idle helper (spawn_tied).
    crate::spawn::spawn_tied(cmd).context("spawning the VMM")
}

/// Report a VMM that exited during boot: name the backend that actually ran (libkrun
/// by default, else cloud-hypervisor) and show the tails of both the guest serial log
/// and the VMM's own stdout/stderr (`<serial>.vmm.log`) — libkrun prints its abort
/// reason there, so surfacing it is what makes a failed boot legible.
fn boot_failure(console: &Path, status: std::process::ExitStatus) -> String {
    let vmm = if crate::vmm::libkrun_selected() {
        "libkrun"
    } else {
        "cloud-hypervisor"
    };
    let vmm_log = console.with_extension("vmm.log");
    let serial = tail(console, 20);
    let vmm_out = tail(&vmm_log, 20);
    // A silent death means the guest never brought its console up — almost always a
    // boot-medium/resource problem rather than a VMM one; say so instead of showing
    // two empty tails.
    let hint = if serial.is_empty() && vmm_out.is_empty() {
        "\n(no output at all: the guest died before its console initialised — \
         e.g. too little --mem for the kernel or boot medium)"
    } else {
        ""
    };
    format!(
        "{vmm} exited during boot ({status})\n--- serial ({}) ---\n{}\n--- vmm ({}) ---\n{}{hint}",
        console.display(),
        serial,
        vmm_log.display(),
        vmm_out,
    )
}

/// Parse a `--mem` value into MiB: `<n>G`, `<n>M`, or a plain MiB count. `None` for
/// anything else (e.g. cloud-hypervisor's richer syntax) — callers skip their check.
pub(crate) fn parse_mem_mib(mem: &str) -> Option<u64> {
    if let Some(g) = mem.strip_suffix(['G', 'g']) {
        return g.parse::<u64>().ok().map(|n| n * 1024);
    }
    if let Some(m) = mem.strip_suffix(['M', 'm']) {
        return m.parse().ok();
    }
    mem.parse().ok()
}

fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// A long-lived guest for one build stage: the stage's rw qcow2 image is booted once
/// directly (with egress via a `vk switch`), and every `RUN` of the stage execs
/// into it — no per-`RUN` reboot. [`VmSession::capture`] copies the current state to a
/// consistent qcow2 (for the instruction cache) and [`VmSession::finish`] shuts down
/// cleanly; the guest's writes are already in the stage image, so there is no commit.
/// A checkpoint's mutated clusters drained from the block device, split by last operation:
/// `(written, discarded)` byte ranges — written clusters to read and push, discarded ones to
/// represent as holes.
pub(crate) type DrainedDirty = (Vec<(u64, u64)>, Vec<(u64, u64)>);

pub(crate) struct VmSession {
    ch: Child,
    addr: SocketAddr,
    /// the stage's rw qcow2 image, booted directly — the guest's writes land in it, so it
    /// IS the stage's result (no separate boot overlay to commit back).
    image: PathBuf,
    switch: Option<Child>,
    /// virtiofsd serving the build context (for `COPY` from the context), if any.
    virtiofsd: Option<Child>,
    work: PathBuf,
    /// Guest device of the ephemeral `--mount=from=scratch` disk (e.g. `/dev/vde`), when one
    /// was attached; `None` = this guest has no writable scratch disk. The executor mounts it
    /// on demand for a `RUN --mount=type=bind,from=scratch,rw` step.
    scratch_dev: Option<String>,
    /// Unix socket the stage overlay's dirty-drain control listener serves on (libkrun build
    /// stages only). `checkpoint_dirty` connects here; `None` = full-capture fallback.
    dirty_socket: Option<PathBuf>,
    /// build-wide cancellation: when the parallel driver aborts a build (a stage failed),
    /// a RUN still executing in this guest is interrupted rather than run to completion.
    /// `None` outside the parallel build (a plain `vk run`).
    cancel: Option<CancellationToken>,
}

/// Guest mountpoint of the build-context virtiofs share (for `COPY` from the context).
pub(crate) const CONTEXT_MOUNT: &str = "/run/virtkit-context";

/// Spawn a `vk switch` giving one VM a userspace LAN + egress over `vsock` (DHCP +
/// DNS + transparent proxy, unrestricted). Returns the switch child and the cmdline
/// fragment the guest agent needs to bring up its tap. Waits for the switch to bind.
#[allow(clippy::too_many_arguments)]
async fn spawn_vm_switch(
    vsock: &Path,
    work: &Path,
    net_port: u32,
    allow_ip: &[String],
    allow_name: &[String],
    extra_listen: &[(PathBuf, std::net::Ipv4Addr)],
    hosts: &[(String, String)],
    reservations: &[(String, String)],
    registry_proxy: Option<(std::net::Ipv4Addr, std::net::SocketAddr)>,
    audit_log: Option<PathBuf>,
    // Where this switch publishes what it forwarded, for the phase's resource line. A build
    // passes its shared scratch, so every stage's switch appends to the one file the build
    // reads at the end; a run passes its own work dir.
    bytes_log: Option<PathBuf>,
    // Force allowlist mode even with empty lists (deny-all) — the CI build phase sets this
    // for a restricted `[egress.build]`. Dev `vk run` passes `false` (unset = unrestricted).
    restrict: bool,
) -> Result<(Child, String)> {
    let (gw, prefix, guest_ip) = crate::net::switch_addrs(RUN_SUBNET)?;
    let mut listen = vsock.to_path_buf().into_os_string();
    listen.push(format!("_{net_port}"));
    // The primary VM's socket is bound to its own address; each sibling's to its assigned IP.
    let mut all_listen = vec![(PathBuf::from(listen), guest_ip)];
    all_listen.extend(extra_listen.iter().cloned());
    let child = crate::switch::spawn(&crate::switch::Spawn {
        listen: all_listen,
        gateway: gw,
        prefix,
        hosts: hosts.to_vec(),
        reservations: reservations.to_vec(),
        allow_ip: allow_ip.to_vec(),
        allow_name: allow_name.to_vec(),
        restrict,
        // Per-service egress overrides are a CI feature (from a service's `variables:`);
        // dev `vk run --compose` siblings share the run policy.
        per_source: Vec::new(),
        registry_proxy,
        log: work.join("switch.log"),
        // Dev `vk run` has no gitlab job trace to surface denials into; the switch's own
        // log (eprintln) is enough interactively.
        denied_log: None,
        // Audit mode (`--audit-egress` / `--build-audit-egress`) records every external
        // domain the guest resolves; the caller prints the summary when the run/build ends.
        audit_log,
        // What the switch forwarded, for the phase's own resource line — into whichever
        // channel the caller reads at the end.
        bytes_log,
    })?;
    let frag = format!(
        " VIRTKIT_NET_PORT={net_port} VIRTKIT_VM_IP={guest_ip}/{prefix} \
         VIRTKIT_VM_GW={gw} VIRTKIT_VM_DNS={gw}"
    );
    Ok((child, frag))
}

/// The qemu/cloud-hypervisor disk format of a stage image, by extension: forked stages
/// are `.qcow2` (a copy-on-write overlay over their parent), bases are raw `.ext4`.
pub(crate) fn disk_format(path: &Path) -> &'static str {
    if path.extension().and_then(|e| e.to_str()) == Some("qcow2") {
        "qcow2"
    } else {
        "raw"
    }
}

/// Spare capacity of a build guest's ephemeral scratch disks (blocks of 4 KiB). Sparse, so
/// the generous ceiling costs nothing until written; it just has to comfortably hold a
/// toolchain unpack (rust is ~2.5 GiB) or a big `./configure` tree.
const SCRATCH_DISK_FREE_BLOCKS: u64 = 32 * 1024 * 1024 * 1024 / 4096;

/// A fresh, empty, sparse ext4 next to `image`, tagged by `role` (`tmpdisk`/`scratchdisk`)
/// so a guest's `/tmp` disk and its `--mount=from=scratch` disk don't collide. Both are
/// ephemeral devices, never part of a stage snapshot; the caller removes them.
fn build_empty_disk(image: &Path, role: &str) -> Result<PathBuf> {
    let stem = image.file_stem().and_then(|s| s.to_str()).unwrap_or("disk");
    let backing = image.with_file_name(format!("{stem}.{role}.ext4"));
    crate::ext4::build_empty(&backing, SCRATCH_DISK_FREE_BLOCKS)
        .with_context(|| format!("creating the {role} disk {}", backing.display()))?;
    Ok(backing)
}

/// The ephemeral disk backing a build guest's `/tmp` (the default; off under `--build-tmp-tmpfs`).
pub(crate) fn build_tmp_disk(image: &Path) -> Result<PathBuf> {
    build_empty_disk(image, "tmpdisk")
}

/// The ephemeral disk backing a stage's `RUN --mount=type=bind,from=scratch,rw` targets.
pub(crate) fn build_scratch_disk(image: &Path) -> Result<PathBuf> {
    build_empty_disk(image, "scratchdisk")
}

/// Boot a stage guest on `image` (a rw qcow2, written in place) and wait for the in-guest
/// agent. Unless `net` is `None`, a `vk switch` gives egress (DHCP + DNS + transparent
/// proxy), restricted to `net`'s allowlist if it has one.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn boot_session(
    cloud_hypervisor: &Path,
    kernel: &Path,
    agent: &Path,
    image: &Path,
    net: &crate::build::BuildNet,
    cpus: u32,
    mem: &str,
    boot_timeout_secs: u64,
    sources: &[PathBuf],
    context: Option<&Path>,
    // `Some` → attach this caller-owned ext4 as a disk-backed /tmp scratch (the default; off
    // under --build-tmp-tmpfs); `None` → a RAM tmpfs /tmp (no device attached, no
    // VIRTKIT_TMP_DEV). The caller owns the disk's lifecycle: it is reused across a stage's
    // source-batch reboots and removed at stage_end, so it never enters the stage snapshot.
    tmp_disk: Option<&Path>,
    // `Some` → attach this caller-owned empty ext4 as the writable scratch disk backing
    // `RUN --mount=type=bind,from=scratch,rw` targets; its guest device is recorded on the
    // returned `VmSession`. Same ephemeral, caller-owned lifecycle as `tmp_disk`.
    scratch_disk: Option<&Path>,
    // `Some((kernel, initramfs))` → `FROM --kernel=image`: boot the stage's RUNs on this
    // extracted image kernel + fullvm preinit initramfs (agent + modules) instead of the
    // pinned build kernel + the plain agent initramfs. `None` = the normal build boot.
    image_kernel: Option<(&Path, &Path)>,
    // `Some(path)` → `vk build --disk`: attach this caller-owned raw disk read-write right
    // after the rootfs, so it is always `/dev/vdb` for the stage's RUNs (sources follow at
    // `vdc`+). Not snapshotted; the caller owns its lifecycle.
    out_disk: Option<&Path>,
    // `Some(path)` → audit mode (`--build-audit-egress`): the build's switch appends every
    // external domain a `RUN` step resolves here (a channel shared across the build's stages),
    // for the post-build "domains contacted" summary. `None` = no audit.
    audit_log: Option<&Path>,
    // `Some(path)` → the build's byte channel (`<scratch>/net.bytes`), shared across its
    // stages the way the audit channel is: each stage's switch appends what it forwarded, and
    // the build sums them into its resource line. `None` = nothing reads it, so nothing counts.
    bytes_log: Option<&Path>,
    cancel: Option<CancellationToken>,
    timings: &Timings,
) -> Result<VmSession> {
    let t_boot = Instant::now();
    let stem = image.file_stem().and_then(|s| s.to_str()).unwrap_or("disk");
    let work = std::env::temp_dir().join(format!("virtkit-session-{}-{stem}", std::process::id()));
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    // The agent boots as PID 1 from a minimal initramfs (just `/init`), then pivots into
    // the ext4 root below — so the agent is never written into the built image. With
    // libkrun it is an unlinked scratch fd: `_cpio` keeps it open until the VMM child
    // (which inherits the fd via pass_fds below) has spawned, i.e. past spawn_vmm.
    let mut pass_fds: Vec<i32> = Vec::new();
    let mut _cpio: Option<crate::scratch::ScratchFile> = None;
    let cpio = if let Some((_, initramfs)) = image_kernel {
        // --kernel=image: fullvm already built the preinit initramfs (agent as /init +
        // the boot-critical modules) from the image; use it as-is.
        initramfs.to_path_buf()
    } else if crate::vmm::libkrun_selected() {
        let s = crate::scratch::scratch(&work, "initramfs.cpio")?;
        let path = s.path.clone();
        pass_fds.push(s.fd());
        _cpio = Some(s);
        path
    } else {
        work.join("initramfs.cpio")
    };
    if image_kernel.is_none() {
        let t_ir = Instant::now();
        crate::initramfs::build_agent_initramfs(agent, &cpio)?;
        timings.probe("boot.initramfs", t_ir.elapsed());
    }
    // Boot the stage's rw qcow2 image directly: it is a CoW overlay over its backing (the
    // base ext4 or the parent stage), so the guest's writes accumulate into it and it
    // becomes the stage's result — no separate boot overlay, no commit. (A raw-rw disk
    // does not present as /dev/vda, which is why every stage image is a qcow2.)
    // Dirty-block tracking for the O(delta) checkpoint capture: the writable stage overlay
    // serves a drain protocol on this socket (libkrun only; cloud-hypervisor lacks the hook and
    // falls back to a full capture + content_diff). `checkpoint_dirty` connects here at each
    // commit. The socket lives in the per-session work dir, out of the guest's reach.
    let dirty_socket = crate::vmm::libkrun_selected().then(|| work.join("dirty.sock"));
    let overlay = match &dirty_socket {
        Some(sock) => {
            crate::vmm::Disk::overlay(image.to_path_buf()).with_dirty_control(sock.clone())
        }
        None => crate::vmm::Disk::overlay(image.to_path_buf()),
    };
    let mut disks: Vec<crate::vmm::Disk> = vec![overlay];
    // `vk build --disk`: the caller-owned target disk, attached read-write immediately after
    // the rootfs so it is always /dev/vdb for the stage's RUNs (before the sources below).
    // Raw + not snapshotted; the RUNs' writes to it are the build artifact.
    if let Some(p) = out_disk {
        disks.push(crate::vmm::Disk::raw(p.to_path_buf(), false));
    }
    // Source stages for COPY --from / RUN --mount=from, attached read-only as the next
    // virtio-blk disks (vdb, vdc, … in order) for the guest to mount and read. A forked
    // source is a qcow2 over its parent (its backing chain is resolved); a base source is
    // a plain raw ext4.
    for src in sources {
        disks.push(crate::vmm::Disk {
            path: src.clone(),
            qcow2: disk_format(src) == "qcow2",
            readonly: true,
            dirty_control_socket: None,
        });
    }
    // Disk-backed /tmp for the build guest (the default; off under --build-tmp-tmpfs): a sparse
    // ext4 on its own virtio-blk device, so a stage's RUN steps can extract gigabytes to /tmp
    // without the ½·RAM cap of a tmpfs — yet, being a separate device, it never enters the stage
    // snapshot (no cache churn). The caller owns the disk's lifecycle (a batched build reuses
    // one disk so /tmp survives the source-subset reboots, and removes it at stage_end).
    // `None` = a RAM tmpfs /tmp: the agent falls back to tmpfs when VIRTKIT_TMP_DEV is absent,
    // so we simply attach no device and set no cmdline var.
    let tmp_dev = tmp_disk.map(|path| {
        let dev = crate::build::vd_name(disks.len());
        disks.push(crate::vmm::Disk {
            path: path.to_path_buf(),
            qcow2: false,
            readonly: false,
            dirty_control_socket: None,
        });
        dev
    });
    // Writable scratch disk for `RUN --mount=type=bind,from=scratch,rw`: an empty rw ext4 on
    // its own device, mounted on demand by the executor at the mount target. Ephemeral and
    // never snapshotted, exactly like the /tmp disk. The device name is recorded on the
    // session so the executor knows where to mount it.
    let scratch_dev = scratch_disk.map(|path| {
        let dev = crate::build::vd_name(disks.len());
        disks.push(crate::vmm::Disk {
            path: path.to_path_buf(),
            qcow2: false,
            readonly: false,
            dirty_control_socket: None,
        });
        format!("/dev/{dev}")
    });
    // The kernel runs the initramfs `/init` (the agent); it then pivots into the ext4
    // named by VIRTKIT_PIVOT. No `init=`/`root=` for the kernel to mount — the agent does.
    let mut cmdline = format!(
        "console=ttyS0 rdinit=/init VIRTKIT_PIVOT=/dev/vda \
         VIRTKIT_HOSTNAME=vm VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
    );
    if let Some(dev) = &tmp_dev {
        cmdline.push_str(&format!(" VIRTKIT_TMP_DEV=/dev/{dev}"));
    }
    // --kernel=image: a modular image kernel has no early hvc0 (console stays on ttyS0)
    // and the preinit reads this to insmod the ride-along modules before the pivot.
    if image_kernel.is_some() {
        cmdline.push_str(" VIRTKIT_KERNEL=image");
    }
    let vsock = work.join("vsock.sock");
    let console = work.join("console.log");

    // Build context for COPY from the context: served read-only over virtiofs and
    // mounted by the agent at CONTEXT_MOUNT (it reads VIRTKIT_VIRTIOFS at boot).
    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    let mut virtiofsd: Option<Child> = None;
    if let Some(ctx) = context {
        let sock = work.join("context.fs.sock");
        if !crate::vmm::libkrun_selected() {
            virtiofsd = Some(crate::spawn::spawn_virtiofsd(&sock, ctx, true, &[], &[])?);
        }
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS=context:{CONTEXT_MOUNT}"));
        shares.push(crate::vmm::FsShare {
            tag: "context".into(),
            socket: sock,
            host_dir: ctx.to_path_buf(),
            read_only: true,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        });
    }

    let mut switch: Option<Child> = None;
    let net_on = !matches!(net, crate::build::BuildNet::None);
    if net_on {
        let (allow_ip, allow_name): (&[String], &[String]) = match net {
            crate::build::BuildNet::Allow { ips, names } => (ips, names),
            _ => (&[], &[]),
        };
        let (child, frag) = spawn_vm_switch(
            &vsock,
            &work,
            NET_VSOCK_PORT,
            allow_ip,
            allow_name,
            &[],
            &[],
            &[],
            None,
            audit_log.map(Path::to_path_buf),
            bytes_log.map(Path::to_path_buf),
            // A restricted build policy (`BuildNet::Allow`, incl. empty = deny) forces
            // allowlist mode; `BuildNet::All` is unrestricted.
            matches!(net, crate::build::BuildNet::Allow { .. }),
        )
        .await?;
        switch = Some(child);
        cmdline.push_str(&frag);
    }

    let mut vsock_ports = vec![crate::vmm::VsockPort::exec(&vsock, VSOCK_PORT)];
    if net_on {
        vsock_ports.push(crate::vmm::VsockPort::bridge(&vsock, NET_VSOCK_PORT));
    }
    // virtio-fs (the context share) requires shared guest memory (shared_mem).
    // --kernel=image boots the extracted image kernel; otherwise the pinned build kernel.
    let boot_kernel = image_kernel.map(|(k, _)| k).unwrap_or(kernel);
    let spec = crate::vmm::VmSpec {
        kernel: boot_kernel.to_path_buf(),
        cmdline,
        disks,
        initramfs: Some(cpio),
        shares,
        vsock_cid: 3,
        vsock_socket: vsock.clone(),
        vsock_ports,
        cpus,
        mem: mem.to_string(),
        shared_mem: context.is_some(),
        net: crate::vmm::Net::None,
        // A stage's RUN can free a lot at once (a package cache, an unpacked tree):
        // report those pages back rather than hold the guest's peak until poweroff.
        // The PCI slot this spends is already counted into MAX_SOURCE_DISKS.
        balloon: true,
        serial_log: console.clone(),
        // build stages boot the pinned kernel (hvc0), never a BYO serial-only kernel.
        console_serial: false,
        pmu: false,
        nested: false,
        api_socket: None,
        pass_fds,
        // `stem` is the stage ext4's name — the closest identity this build VM has.
        proc_name: crate::vmm::resolve_proc_name(stem),
    };
    let vmm = crate::vmm::selected(cloud_hypervisor);
    let addr = crate::vmm::exec_addr(&vsock, VSOCK_PORT);
    let t_spawn = Instant::now();
    let mut ch = spawn_vmm(vmm.as_ref(), &spec)?;
    timings.probe("boot.spawn", t_spawn.elapsed());
    let t_wait = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(boot_timeout_secs);
    loop {
        if let Some(status) = ch.try_wait()? {
            bail!("{}", boot_failure(&console, status));
        }
        if vk_core::status::get_status(&addr).await.is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = ch.kill();
            let _ = ch.wait();
            for c in [switch.as_mut(), virtiofsd.as_mut()].into_iter().flatten() {
                let _ = c.kill();
                let _ = c.wait();
            }
            bail!(
                "VM not ready after {boot_timeout_secs}s\n{}",
                tail(&console, 20)
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    timings.probe("boot.wait", t_wait.elapsed());
    timings.probe("boot.session", t_boot.elapsed());
    Ok(VmSession {
        ch,
        addr,
        image: image.to_path_buf(),
        switch,
        virtiofsd,
        work,
        scratch_dev,
        dirty_socket,
        cancel,
    })
}

impl VmSession {
    /// Guest device of this session's writable scratch disk, if one was attached at boot.
    pub(crate) fn scratch_dev(&self) -> Option<&str> {
        self.scratch_dev.as_deref()
    }

    /// Run `command` (optionally as `user`) in the live guest, relaying its output through
    /// `sink`; returns its exit code.
    pub(crate) async fn exec(
        &self,
        command: &[String],
        user: Option<String>,
        sink: &crate::executor::OutputSink,
    ) -> Result<i32> {
        let r = crate::executor::exec_script(
            &self.addr,
            command,
            Vec::new(),
            user,
            sink,
            self.cancel.as_ref(),
        )
        .await
        .context("running the command in the guest")?;
        Ok(r.code.unwrap_or(0))
    }

    /// Run a guest command (as root) and report whether it exited 0 — for best-effort
    /// quiesce helpers where a missing binary or non-zero exit just means "fall back".
    async fn guest_ok(&self, argv: &[&str]) -> bool {
        let cmd: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        matches!(
            crate::executor::exec_script(
                &self.addr,
                &cmd,
                Vec::new(),
                None,
                &crate::executor::OutputSink::Inherit,
                None,
            )
            .await,
            Ok(r) if r.code == Some(0)
        )
    }

    /// Capture a consistent point-in-time copy of the live stage image (a qcow2) to `out`,
    /// for the cache push to read directly via the native qcow2 reader — no `qemu-img
    /// convert` to a flat raw (that wrote a whole image per instruction, the dominant disk
    /// IO of cache-on).
    ///
    /// The guest fs is quiesced first so the copy is consistent: the agent's built-in
    /// `fsfreeze` is preferred (it flushes + marks the ext4 clean), falling back to a plain
    /// `sync`. The freeze MUST be thawed afterwards (even on copy failure) or the guest
    /// hangs. cloud-hypervisor holds an advisory write lock on the live image that a plain
    /// `std::fs::copy` ignores; the copy keeps the same backing reference (opened
    /// read-only), so the reader resolves unchanged clusters through it.
    pub(crate) async fn capture(&self, out: &Path, timings: &Timings) -> Result<()> {
        let t = Instant::now();
        let frozen = self.freeze().await;
        let copied = std::fs::copy(&self.image, out);
        self.thaw(frozen).await;
        copied.with_context(|| format!("copying {} -> {}", self.image.display(), out.display()))?;
        timings.probe("snap.capture", t.elapsed());
        Ok(())
    }

    /// Quiesce the guest fs so the live image is a consistent point-in-time source: `fsfreeze`
    /// (flushes + marks the ext4 clean) when the guest supports it, else a plain `sync`.
    /// Returns whether the freeze took (so [`Self::thaw`] knows to unfreeze). The freeze MUST
    /// be paired with `thaw` even on error, or the guest hangs.
    pub(crate) async fn freeze(&self) -> bool {
        let frozen = self.guest_ok(&[GUEST_AGENT, "fsfreeze", "-f", "/"]).await;
        if !frozen {
            let _ = crate::executor::exec_script(
                &self.addr,
                &["sync".to_string()],
                Vec::new(),
                None,
                &crate::executor::OutputSink::Inherit,
                None,
            )
            .await;
        }
        frozen
    }

    /// Discard the guest fs's free blocks (`vk-agent fstrim /`) so a following checkpoint's
    /// allocation map lists only live data — blocks freed by files written and deleted since
    /// the last checkpoint are released and never enter the delta. Best-effort: a fs/backend
    /// without discard support just keeps them (a larger, still-correct delta). Run before the
    /// freeze — a frozen fs rejects the discard.
    pub(crate) async fn trim(&self) {
        let _ = self.guest_ok(&[GUEST_AGENT, "fstrim", "/"]).await;
    }

    /// Undo a [`Self::freeze`]; `frozen` is that call's return.
    pub(crate) async fn thaw(&self, frozen: bool) {
        if frozen {
            let _ = self.guest_ok(&[GUEST_AGENT, "fsfreeze", "-u", "/"]).await;
        }
    }

    /// The live stage overlay (the booted rw qcow2). During a freeze it is a stable snapshot
    /// source; the dirty-tracked build path reads its delta extents directly from it.
    pub(crate) fn image(&self) -> &Path {
        &self.image
    }

    /// Whether this guest's block device tracks dirty clusters (libkrun build stages). When
    /// true, [`Self::drain_dirty`] yields the O(delta) changed extents instead of a whole-image
    /// diff.
    pub(crate) fn supports_dirty(&self) -> bool {
        self.dirty_socket.is_some()
    }

    /// Drain the block device's dirty-cluster set over the control socket: the guest-logical
    /// byte ranges mutated since the previous drain, split into `(written, discarded)` — clusters
    /// whose last touch put data there vs. clusters freed or zeroed (to hole, not read). Also
    /// flushes the device's writes to the image file, so a subsequent host-side read of `image()`
    /// sees them. Freeze the guest first (so no write races the drain). Errs if dirty tracking is
    /// disabled.
    pub(crate) fn drain_dirty(&self) -> Result<DrainedDirty> {
        use std::io::{Read, Write};
        let sock = self
            .dirty_socket
            .as_ref()
            .context("drain_dirty: dirty tracking not enabled for this guest")?;
        let mut conn = std::os::unix::net::UnixStream::connect(sock)
            .with_context(|| format!("connecting dirty-control socket {}", sock.display()))?;
        conn.write_all(b"D").context("dirty-control: send DRAIN")?;
        // Two blocks back to back: written ranges, then discarded ranges. Each is `u32 count`
        // then `count × (u64 offset, u64 len)` little-endian.
        let mut read_block = |label: &str| -> Result<Vec<(u64, u64)>> {
            let mut count = [0u8; 4];
            conn.read_exact(&mut count)
                .with_context(|| format!("dirty-control: read {label} range count"))?;
            let count = u32::from_le_bytes(count) as usize;
            // The peer is the trusted in-process VMM child, but a stray count would size the read
            // buffer directly — reject an implausible one rather than pre-allocate up to ~64 GiB.
            // Ranges are coalesced whole clusters, so even a fully fragmented multi-TiB image
            // stays far below this cap.
            const MAX_DIRTY_RANGES: usize = 16 * 1024 * 1024;
            ensure!(
                count <= MAX_DIRTY_RANGES,
                "dirty-control: implausible {label} range count {count} (> {MAX_DIRTY_RANGES})",
            );
            let mut buf = vec![0u8; count * 16];
            conn.read_exact(&mut buf)
                .with_context(|| format!("dirty-control: read {label} ranges"))?;
            let mut ranges = Vec::with_capacity(count);
            for c in buf.chunks_exact(16) {
                let off = u64::from_le_bytes(c[..8].try_into().unwrap());
                let len = u64::from_le_bytes(c[8..16].try_into().unwrap());
                ranges.push((off, len));
            }
            Ok(ranges)
        };
        let written = read_block("written")?;
        let discarded = read_block("discarded")?;
        Ok((written, discarded))
    }

    /// Flush the stage disk's write-back cache to the host image over the block-control socket,
    /// so a later host read (export / cache) sees a complete image once the VMM is killed. A
    /// no-op when the guest has no control socket — a plain run (whose image is discarded) or
    /// cloud-hypervisor (which writes through). Best-effort: an error is logged and the caller
    /// kills the VMM regardless.
    fn flush_disk(&self) {
        use std::io::{Read, Write};
        let Some(sock) = self.dirty_socket.as_ref() else {
            return;
        };
        let flush = || -> Result<()> {
            let mut conn = std::os::unix::net::UnixStream::connect(sock)
                .with_context(|| format!("connecting block-control socket {}", sock.display()))?;
            conn.write_all(b"F").context("block-control: send FLUSH")?;
            let mut ack = [0u8; 1];
            conn.read_exact(&mut ack)
                .context("block-control: read FLUSH ack")?;
            ensure!(ack[0] == 0, "block-control: FLUSH reported an error");
            Ok(())
        };
        if let Err(e) = flush() {
            eprintln!(
                "virtkit: flushing the stage disk before shutdown failed ({e:#}) — the image \
                 may be incomplete"
            );
        }
    }

    /// Shut the guest down and reclaim the VM. The stage image is the booted disk, so its writes
    /// are already persisted in place — there is nothing to commit, only to make durable before
    /// the kill.
    ///
    /// One path for every backend: quiesce the guest fs (so the image is a consistent
    /// point-in-time), flush the block device's write-back cache to the host image, then kill.
    /// libkrun keeps guest writes in that cache until an explicit flush, so a bare SIGKILL would
    /// truncate the stage qcow2 (an L2 entry past EOF a later native read rejects) — [`flush_disk`]
    /// makes it durable first. cloud-hypervisor writes through and a plain run discards its image,
    /// so both have no control socket and the flush is a no-op.
    pub(crate) async fn finish(mut self) -> Result<()> {
        // `cleanup` removes the agent-created ephemeral mountpoints/stubs (so they do not litter
        // the image) and then quiesces — all native, so it works on a shell-less `FROM scratch`
        // stage. Fall back to a native fsfreeze, then a shell `sync`, if an older agent lacks
        // cleanup. The guest is killed right after, so no thaw is needed.
        let cleaned = self.guest_ok(&[GUEST_AGENT, "cleanup"]).await;
        if !cleaned {
            // `cleanup` is what drops the agent-created mountpoints and stubs, and the in-image
            // record naming them, so an image committed from this guest can keep both — and a
            // build on top of it would then read that record as its own. Silence here is what
            // used to make that indistinguishable from a clean stage.
            eprintln!(
                "virtkit: the guest's cleanup step did not run — an image committed from this \
                 guest may keep the agent's ephemeral mountpoints"
            );
        }
        let quiesced = cleaned || self.guest_ok(&[GUEST_AGENT, "fsfreeze", "-f", "/"]).await;
        if !quiesced {
            let _ = crate::executor::exec_script(
                &self.addr,
                &["sync".to_string()],
                Vec::new(),
                None,
                &crate::executor::OutputSink::Inherit,
                None,
            )
            .await;
        }
        self.flush_disk();
        let _ = self.ch.kill();
        let _ = self.ch.wait();
        // The switch is stopped rather than killed, for the same reason a run stops its own:
        // a stage whose last act is a download has that download in the counters and not yet
        // in the channel, and the build reads the channel after every stage has gone.
        if let Some(c) = self.switch.take() {
            stop_switch(c);
        }
        if let Some(c) = self.virtiofsd.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.work);
        Ok(())
    }
}

impl Drop for VmSession {
    fn drop(&mut self) {
        // a session dropped without finish() (e.g. a failed RUN) must not leak the VM.
        let _ = self.ch.kill();
        let _ = self.ch.wait();
        // The switch is stopped rather than killed, for the same reason a run stops its own:
        // a stage whose last act is a download has that download in the counters and not yet
        // in the channel, and the build reads the channel after every stage has gone.
        if let Some(c) = self.switch.take() {
            stop_switch(c);
        }
        if let Some(c) = self.virtiofsd.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exec_channel_never_reruns_an_entrypoint_that_is_already_pid_1() {
        let image_entrypoint = ["/prepare-machine.sh".to_string()];
        let primary = vk_core::runcfg::RunConfig {
            entrypoint: vec!["/prepare-machine.sh".into()],
            cmd: vec!["serve".into()],
            ..Default::default()
        };
        // the axes that keep the agent (or the image's init) at PID 1 wrap a trailing
        // command in the image's entrypoint and fall back to a --primary service's own argv
        for init in [InitSource::Default, InitSource::Image] {
            let (entrypoint, fallback) = exec_channel_argv(init, &image_entrypoint, Some(&primary));
            assert_eq!(entrypoint, image_entrypoint);
            assert_eq!(fallback, ["/prepare-machine.sh", "serve"]);
        }
        // under `--init entrypoint` that argv is PID 1 already, so neither runs again
        let (entrypoint, fallback) =
            exec_channel_argv(InitSource::Entrypoint, &image_entrypoint, Some(&primary));
        assert!(entrypoint.is_empty(), "a trailing command runs unwrapped");
        assert!(
            fallback.is_empty(),
            "no command falls through to the boot-info probe"
        );
        // the `-f`/plain-image shape: no --primary config, so only the entrypoint differs
        assert_eq!(
            exec_channel_argv(InitSource::Image, &image_entrypoint, None),
            (&image_entrypoint[..], Vec::new())
        );
        assert_eq!(
            exec_channel_argv(InitSource::Entrypoint, &image_entrypoint, None),
            (&[][..], Vec::new())
        );
    }

    #[test]
    fn handoff_tokens_name_the_axis_the_guest_agent_reads() {
        // default: the agent keeps PID 1, so there is nothing to hand off
        assert_eq!(InitSource::Default.handoff_tokens(), "");
        // the image's own init needs its path spelled out on the cmdline
        assert_eq!(
            InitSource::Image.handoff_tokens(),
            " VIRTKIT_INIT=image VIRTKIT_HANDOFF=/sbin/init"
        );
        // the entrypoint argv rides the boot config instead, so no handoff path here —
        // one with spaces in it could not survive the kernel cmdline
        assert_eq!(
            InitSource::Entrypoint.handoff_tokens(),
            " VIRTKIT_INIT=entrypoint"
        );
        // both image axes hand PID 1 over, so both take the preinit boot medium
        assert!(InitSource::Image.is_image() && InitSource::Entrypoint.is_image());
        assert!(!InitSource::Default.is_image());
        // the axis names itself the way the user spelled it, for the guard messages
        assert_eq!(
            [
                InitSource::Default.to_string(),
                InitSource::Image.to_string(),
                InitSource::Entrypoint.to_string()
            ],
            ["default", "image", "entrypoint"]
        );
    }

    #[test]
    fn service_size_overrides_layer_over_the_compose_declaration() {
        let yaml = "services:\n\
             \x20 db:\n    image: d\n    x-virtkit: { cpus: 2, mem: 512M }\n\
             \x20 web:\n    image: w\n";
        let mut units = crate::compose::parse(yaml, Path::new("/b"), &|_| None).unwrap();
        // the flag wins over the marker where given, sets an unmarked service, and
        // leaves everything unnamed alone
        apply_service_sizes(
            &mut units,
            &[("web".into(), 4)],
            &[("db".into(), "2G".into())],
        )
        .unwrap();
        let by = |n: &str| units.iter().find(|u| u.name == n).unwrap();
        assert_eq!(
            (by("db").cpus, by("db").mem.as_deref()),
            (Some(2), Some("2G"))
        );
        assert_eq!((by("web").cpus, by("web").mem.as_deref()), (Some(4), None));
        // a name matching no declared service is an error naming the declared set
        let err = apply_service_sizes(&mut units, &[("nope".into(), 1)], &[]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--service-cpus") && msg.contains("db, web"),
            "{msg}"
        );
    }

    #[test]
    fn nesting_ors_the_request_with_the_primary_service_marker() {
        let units = crate::compose::parse(
            "services:\n\
             \x20 builder:\n    image: b\n    x-virtkit: { nested: true }\n\
             \x20 web:\n    image: w\n",
            Path::new("/b"),
            &|_| None,
        )
        .unwrap();
        let idx = |n: &str| Some(units.iter().position(|u| u.name == n).unwrap());
        let marker = |n: Option<usize>| primary_nested_marker(&units, n);
        // either side asking is enough, and neither asking leaves it off
        assert!(!effective_nested(false, marker(idx("web"))));
        assert!(effective_nested(true, marker(idx("web"))));
        assert!(effective_nested(false, marker(idx("builder"))));
        assert!(effective_nested(true, marker(idx("builder"))));
        // no primary (compose up): a nesting sibling is its own boot's business, not the
        // primary spec's — this is the case a refactor is likeliest to conflate
        assert!(!marker(None));
        assert!(!effective_nested(false, marker(None)));
    }

    #[test]
    fn compose_build_units_merge_services_sharing_a_dockerfile() {
        // a + b share one context/Dockerfile (differ only by target) → one multi-target
        // unit (their common stages build once); c's context differs, d is a pulled image →
        // each its own unit. e matches a exactly but for a named context, which its plan reads
        // and a's does not, so it must not join their unit.
        let yaml = "services:\n\
             \x20 a:\n    build:\n      context: ./ctx\n      target: sa\n\
             \x20 b:\n    build:\n      context: ./ctx\n      target: sb\n\
             \x20 c:\n    build:\n      context: ./other\n      target: sc\n\
             \x20 d:\n    image: redis:7\n\
             \x20 e:\n    build:\n      context: ./ctx\n      target: sa\n\
             \x20     additional_contexts:\n        tools: ./tools\n";
        let units = crate::compose::parse(yaml, Path::new("/base"), &|_| None).unwrap();
        let selected: Vec<usize> = (0..units.len()).collect();
        let built = compose_build_units(&[], &units, &selected, |_| None);
        assert_eq!(built.len(), 4, "a+b merge; c, d and e stand alone");
        // the merged unit carries both a and b as targets, by their stage selectors.
        let merged = built.iter().find(|u| u.targets.len() == 2).unwrap();
        let mut targets: Vec<(&str, &str)> = merged
            .targets
            .iter()
            .map(|t| (t.label.as_str(), t.selector.as_deref().unwrap()))
            .collect();
        targets.sort();
        assert_eq!(targets, [("a", "sa"), ("b", "sb")]);
        // exactly one unit is a pulled image (d).
        let images = built
            .iter()
            .filter(|u| matches!(u.input, crate::build::UnitInput::Image(_)))
            .count();
        assert_eq!(images, 1);
    }

    #[test]
    fn eager_build_selection_defers_profiled_builds_but_keeps_image_services() {
        // web: no profile → eager. extra: a build behind the `debug` profile → profiled-down,
        // deferred to on-demand start. img: an image service behind `debug` → can't build on
        // demand, so it must be materialized up front regardless.
        let yaml = "services:\n\
             \x20 web:\n    build: ./web\n\
             \x20 extra:\n    build: ./extra\n    profiles: [debug]\n\
             \x20 img:\n    image: redis:7\n    profiles: [debug]\n";
        let units = crate::compose::parse(yaml, Path::new("/base"), &|_| None).unwrap();
        let idx = |n: &str| units.iter().position(|u| u.name == n).unwrap();
        let order = crate::compose::boot_order(&units).unwrap();
        // no active profiles, no --primary: the profile-enabled set boots.
        let on = crate::compose::enabled(&units, &[]);
        let selected = eager_build_selection(&units, &order, None, &on);

        assert!(
            selected.contains(&idx("web")),
            "an eager service is built up front"
        );
        assert!(
            selected.contains(&idx("img")),
            "an image: service is always materialized — it can't build on demand"
        );
        assert!(
            !selected.contains(&idx("extra")),
            "a profiled-down build: service is deferred to its first `vk service up`"
        );
        // Never a subset of the eager boot set: everything `on` boots, so everything `on`
        // must be built up front.
        assert!(
            (0..units.len()).all(|i| !on[i] || selected.contains(&i)),
            "selected must cover the whole eager start set"
        );
    }

    #[test]
    fn compose_build_selection_scopes_by_profile_and_primary() {
        // dev depends on redis+mysql; runner is behind the `runner` profile; cache is an
        // image service behind `debug`. Mirrors the wab dev-LAN shape.
        let yaml = "services:\n\
             \x20 dev:\n    build: ./dev\n    depends_on: [redis, mysql]\n\
             \x20 redis:\n    build: ./redis\n\
             \x20 mysql:\n    build: ./mysql\n\
             \x20 runner:\n    build: ./runner\n    profiles: [runner]\n\
             \x20 cache:\n    image: redis:7\n    profiles: [debug]\n";
        let units = crate::compose::parse(yaml, Path::new("/base"), &|_| None).unwrap();
        let idx = |n: &str| units.iter().position(|u| u.name == n).unwrap();
        let names = |sel: Vec<usize>| {
            let mut v: Vec<&str> = sel.iter().map(|&i| units[i].name.as_str()).collect();
            v.sort();
            v
        };

        // No --profile / --primary: the profile-enabled set — every service with no profile
        // (dev, redis, mysql) plus always-materialized image services (cache), but NOT the
        // profiled-down build services (runner). This is what a `vk run --compose` boots.
        let sel = compose_build_selection(&units, &[], None).unwrap();
        assert_eq!(names(sel.clone()), ["cache", "dev", "mysql", "redis"]);
        assert!(
            !sel.contains(&idx("runner")),
            "a profiled build service is not built by default"
        );

        // --primary dev: the boot set — dev + its closure (redis, mysql) + image services
        // (cache), but NOT the profiled-down build service `runner`.
        let sel = compose_build_selection(&units, &[], Some("dev")).unwrap();
        assert_eq!(names(sel.clone()), ["cache", "dev", "mysql", "redis"]);
        assert!(
            !sel.contains(&idx("runner")),
            "a profiled build service is deferred"
        );

        // --profile runner (no primary): the enabled set now includes runner, plus the
        // always-materialized image service.
        let sel = compose_build_selection(&units, &["runner".to_string()], None).unwrap();
        assert!(sel.contains(&idx("runner")) && sel.contains(&idx("cache")));

        // --primary on a profiled build service builds it (plus its closure, which is empty
        // here) and the image services — no profile needed to reach it as the primary.
        let sel = compose_build_selection(&units, &[], Some("runner")).unwrap();
        assert_eq!(names(sel), ["cache", "runner"]);

        // An unknown --profile matches no service, so it is a silent no-op: the selection is
        // exactly the default profile-enabled set, not an error.
        let sel = compose_build_selection(&units, &["nope".to_string()], None).unwrap();
        assert_eq!(names(sel), ["cache", "dev", "mysql", "redis"]);

        // An unknown --primary is a clear error, not a silent empty build.
        assert!(compose_build_selection(&units, &[], Some("nope")).is_err());
    }

    #[test]
    fn host_exec_serve_args_gate_the_wrapper() {
        let listen = Path::new("/run/vsock.sock_1100");
        // no wrapper: a bare unrestricted serve, no --exec-wrapper* flags
        assert_eq!(
            host_exec_serve_args(listen, None, &["LC_*".into()]),
            ["-s", "/run/vsock.sock_1100", "serve"].map(OsString::from)
        );
        // a wrapper carries its client-env globs through; none without it
        assert_eq!(
            host_exec_serve_args(
                listen,
                Some(Path::new("/opt/allow")),
                &["LC_*".into(), "TERM".into()]
            ),
            [
                "-s",
                "/run/vsock.sock_1100",
                "serve",
                "--exec-wrapper",
                "/opt/allow",
                "--exec-wrapper-env",
                "LC_*",
                "--exec-wrapper-env",
                "TERM",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn status_poll_period_tracks_the_timeout_up_to_its_cap() {
        // A timeout shorter than the cap is polled at its own resolution, so the host does
        // not outlast the guest's watchdog by several times the timeout.
        assert_eq!(status_poll_period(Some(3)), Duration::from_secs(3));
        // Longer ones settle at the cap. 0 arms no watchdog, so there is no self-poweroff to
        // catch promptly and nothing bounds how late the host may notice; it polls slower.
        assert_eq!(status_poll_period(Some(1800)), Duration::from_secs(10));
        assert_eq!(status_poll_period(Some(0)), Duration::from_secs(60));
        // Never zero: the loop sleeps this between probes, so it must make progress.
        assert!(!status_poll_period(Some(0)).is_zero());
    }

    #[test]
    fn user_script_preserves_argv_boundaries() {
        // several words: an argv — quoting keeps `sh -c '…'` intact end to end.
        let argv = ["sh", "-c", "echo PING | nc redis 6390"].map(String::from);
        assert_eq!(user_script(&argv), "'sh' '-c' 'echo PING | nc redis 6390'");
        // one word with spaces: a shell one-liner, verbatim.
        assert_eq!(user_script(&["cd /x && make".to_string()]), "cd /x && make");
        // plain argv stays a plain command line.
        assert_eq!(
            user_script(&["cargo", "build", "--release"].map(String::from)),
            "'cargo' 'build' '--release'"
        );
        // empty: the boot-info probe.
        assert!(user_script(&[]).starts_with("echo PID1="));
        // embedded single quotes survive the quoting.
        assert_eq!(
            user_script(&["echo", "it's"].map(String::from)),
            "'echo' 'it'\\''s'"
        );
    }

    #[test]
    fn guest_command_body_applies_entrypoint_and_workdir() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // A trailing command with an image entrypoint: the entrypoint is prepended,
        // docker-run style, and the whole argv is quoted (no shell-one-liner shorthand).
        assert_eq!(
            guest_command_body(&s(&["--version"]), &s(&["/app/bin"]), "/app", false, &[]),
            "cd '/app' && '/app/bin' '--version'"
        );
        // No entrypoint: a single word stays a shell one-liner, run in the image workdir.
        assert_eq!(
            guest_command_body(&s(&["make test"]), &[], "/src", false, &[]),
            "cd '/src' && make test"
        );
        // The --workdir share overrides the image workdir (its outputs land on the host).
        assert_eq!(
            guest_command_body(&s(&["ls"]), &s(&["/entry"]), "/app", true, &[]),
            format!("cd {} && '/entry' 'ls'", sh_quote(WORKDIR_MOUNT))
        );
        // A `/` (or empty) image workdir emits no cd — `/` is the default.
        assert_eq!(guest_command_body(&s(&["ls"]), &[], "/", false, &[]), "ls");
        assert_eq!(guest_command_body(&s(&["ls"]), &[], "", false, &[]), "ls");
        // No trailing command: the fallback (a --primary entrypoint+cmd) runs, in workdir.
        assert_eq!(
            guest_command_body(
                &[],
                &s(&["/entry"]),
                "/app",
                false,
                &s(&["/entry", "serve"])
            ),
            "cd '/app' && '/entry' 'serve'"
        );
        // No command and no fallback: the boot-info probe. This is the `--init entrypoint`
        // shape — the driver passes no entrypoint and no fallback there, since that argv is
        // PID 1 already, so a trailing command runs unwrapped and none repeats it.
        assert!(guest_command_body(&[], &[], "", false, &[]).starts_with("echo PID1="));
        assert_eq!(
            guest_command_body(&s(&["sh", "-c", "id"]), &[], "/app", false, &[]),
            "cd '/app' && 'sh' '-c' 'id'"
        );
    }

    #[test]
    fn encode_ssh_keys_cmdline_shape() {
        // type + base64 survive; the comment is dropped; entries join on commas.
        let keys = [
            "ssh-ed25519 AAAAC3Nza me@host".to_string(),
            "ssh-rsa AAAAB3Nza".to_string(),
        ];
        assert_eq!(
            encode_ssh_keys(&keys).unwrap(),
            "ssh-ed25519:AAAAC3Nza,ssh-rsa:AAAAB3Nza"
        );
        // a bare word is not an OpenSSH `type base64` line.
        assert!(encode_ssh_keys(&["garbage".to_string()]).is_err());
    }

    #[test]
    fn parse_ssh_user_rejects_cmdline_breakers() {
        // portable login names pass through unchanged.
        assert_eq!(parse_ssh_user("dev").unwrap(), "dev");
        assert_eq!(parse_ssh_user("build-bot_1.0").unwrap(), "build-bot_1.0");
        // whitespace or `=` would corrupt the whitespace-split kernel cmdline.
        assert!(parse_ssh_user("").is_err());
        assert!(parse_ssh_user("foo bar").is_err());
        assert!(parse_ssh_user("a=b").is_err());
    }

    #[test]
    fn remove_stale_sockets_spares_caller_files() {
        let dir = std::env::temp_dir().join(format!("virtkit-stale-{}", std::process::id()));
        let svc = dir.join("svc-db");
        let deep = dir.join("data"); // non-svc subdir: not descended into
        std::fs::create_dir_all(&svc).unwrap();
        std::fs::create_dir_all(&deep).unwrap();
        use std::os::unix::net::UnixListener;
        let _a = UnixListener::bind(dir.join("vsock.sock")).unwrap();
        let _b = UnixListener::bind(svc.join("vsock.sock_4444")).unwrap();
        let _c = UnixListener::bind(deep.join("kept.sock")).unwrap();
        std::fs::write(dir.join("vsock.sock.notes"), "caller's").unwrap();
        remove_stale_sockets(&dir).unwrap();
        assert!(!dir.join("vsock.sock").exists());
        assert!(!svc.join("vsock.sock_4444").exists());
        assert!(deep.join("kept.sock").exists()); // non-svc dirs are not descended
        assert!(dir.join("vsock.sock.notes").exists()); // caller's file untouched
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssh_pubkeys_in_reads_standard_identities() {
        let dir = std::env::temp_dir().join(format!("virtkit-sshkeys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("id_ed25519.pub"), "ssh-ed25519 AAA me@host\n").unwrap();
        std::fs::write(dir.join("id_rsa.pub"), "").unwrap(); // empty file: skipped
        let keys = ssh_pubkeys_in(&dir);
        assert_eq!(keys, ["ssh-ed25519 AAA me@host".to_string()]);
        assert!(ssh_pubkeys_in(&dir.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Boot a session with a read-only source disk, mount it in the guest with the
    /// agent's native `mount`, and read a file from it — the COPY --from primitive.
    /// Heavy (boots a microVM); run with the runtime paths:
    ///   VIRTKIT_T_CH=… VIRTKIT_T_KERNEL=… VIRTKIT_T_AGENT=… \
    ///   VIRTKIT_T_ROOT=<bootable ext4> VIRTKIT_T_DATA=<ext4 with /payload.txt> \
    ///   cargo test --target x86_64-unknown-linux-gnu -- --ignored mount_source_disk
    #[test]
    #[ignore]
    fn mount_source_disk() {
        let p = |k: &str| std::env::var_os(k).map(PathBuf::from).expect(k);
        let (ch, kernel, agent, root, data) = (
            p("VIRTKIT_T_CH"),
            p("VIRTKIT_T_KERNEL"),
            p("VIRTKIT_T_AGENT"),
            p("VIRTKIT_T_ROOT"),
            p("VIRTKIT_T_DATA"),
        );
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let s = boot_session(
                &ch,
                &kernel,
                &agent,
                &root,
                &crate::build::BuildNet::None,
                1,
                "1G",
                120,
                &[data],
                None, // context
                None, // tmp_disk
                None, // scratch_disk
                None, // image_kernel (--kernel=image)
                None, // out_disk (--disk)
                None, // audit_log
                None, // bytes_log
                None, // cancel
                &Timings::new(),
            )
            .await
            .expect("boot_session");
            let mount = [
                "/usr/local/bin/vk-agent".to_string(),
                "mount".into(),
                "--ro".into(),
                "/dev/vdb".into(),
                "/mnt/src".into(),
            ];
            let sink = crate::executor::OutputSink::Inherit;
            assert_eq!(
                s.exec(&mount, None, &sink).await.unwrap(),
                0,
                "agent mount failed"
            );
            let read = [
                "sh".to_string(),
                "-c".into(),
                "grep -q MARKER-FROM-VDB /mnt/src/payload.txt".into(),
            ];
            assert_eq!(
                s.exec(&read, None, &sink).await.unwrap(),
                0,
                "reading source failed"
            );
            s.finish().await.unwrap();
        });
    }

    /// Stands in for a VMM: `cat`s the first disk — i.e. opens a boot medium by path.
    struct CatVmm;
    impl crate::vmm::Vmm for CatVmm {
        fn command(&self, spec: &crate::vmm::VmSpec) -> Command {
            let mut cmd = Command::new("cat");
            cmd.arg(&spec.disks[0].path);
            cmd
        }
        fn name(&self) -> &'static str {
            "cat"
        }
    }

    // A scratch fd listed in pass_fds must survive the exec at the same number, so the
    // spawned VMM can open its /proc/self/fd/<n> path (the fd is CLOEXEC otherwise).
    #[test]
    fn pass_fds_survive_exec() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("vk-passfd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut medium = crate::scratch::scratch(&dir, "medium").unwrap();
        medium.file.write_all(b"boot medium").unwrap();
        let spec = crate::vmm::VmSpec {
            kernel: "/dev/null".into(),
            cmdline: String::new(),
            disks: vec![crate::vmm::Disk {
                path: medium.path.clone(),
                qcow2: false,
                readonly: true,
                dirty_control_socket: None,
            }],
            initramfs: None,
            shares: Vec::new(),
            vsock_cid: 3,
            vsock_socket: dir.join("vsock.sock"),
            vsock_ports: Vec::new(),
            cpus: 1,
            mem: "1G".into(),
            shared_mem: false,
            net: crate::vmm::Net::None,
            balloon: false,
            serial_log: dir.join("console.log"),
            console_serial: false,
            pmu: false,
            nested: false,
            api_socket: None,
            pass_fds: vec![medium.fd()],
            proc_name: "vk:test".into(),
        };
        let mut child = spawn_vmm(&CatVmm, &spec).unwrap();
        assert!(child.wait().unwrap().success());
        let out = std::fs::read(spec.serial_log.with_extension("vmm.log")).unwrap();
        assert_eq!(out, b"boot medium");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refused_state_dir_names_the_run_holding_it() {
        let dir = std::env::temp_dir().join(format!("vk-statelock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A second descriptor on the same directory, so the holder can be looked up the
        // way the refusal path does — through the fd it already failed to lock.
        let probe = std::fs::File::open(&dir).unwrap();
        assert!(
            flock_holder(&probe).is_none(),
            "an unlocked dir has no holder"
        );
        let held = lock_state_dir(&dir).unwrap();

        // flock keys on the open file description, so a second acquisition through a
        // fresh fd is refused even from the process already holding it — which is what
        // makes this testable without spawning a second vk.
        let refusal = lock_state_dir(&dir).unwrap_err().to_string();
        assert!(
            refusal.contains(&dir.display().to_string())
                && refusal.contains("pass a different --state-dir"),
            "the refusal must name the dir and the way out: {refusal}"
        );
        // Naming the holder is best-effort: `/proc/locks` keys on the superblock device,
        // which a btrfs subvolume's `st_dev` does not match, so a `TMPDIR` there resolves
        // nobody. Where procfs does name one, it has to be this process. Matched on the
        // pid alone — the age is recomputed per lookup, so a run straddling a second
        // boundary between the two renders two different strings.
        let pid = format!("pid {}", std::process::id());
        match flock_holder(&probe) {
            Some(who) => {
                assert!(
                    who.starts_with(&pid),
                    "expected this process as the holder, got {who}"
                );
                assert!(
                    refusal.contains(&pid),
                    "the refusal must name the holder: {refusal}"
                );
            }
            None => eprintln!("skipped: /proc/locks names no holder for {}", dir.display()),
        }

        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_the_flock_holder_out_of_proc_locks() {
        let want = "fc:01:22151305";
        let locks = "\
1: POSIX  ADVISORY  WRITE 1111 fc:01:22151305 0 EOF
2: FLOCK  ADVISORY  WRITE 2222 fc:01:22151305 0 EOF
2: -> FLOCK  ADVISORY  WRITE 3333 fc:01:22151305 0 EOF
3: FLOCK  ADVISORY  WRITE 4444 fc:01:99999999 0 EOF
";
        // The FLOCK holder, not the POSIX lock on the same inode, not a lock on another
        // inode, and not the request blocked behind the holder.
        assert_eq!(holder_pid(locks, want), Some(2222));
        assert_eq!(holder_pid(locks, "00:00:1"), None);
        // A request blocked behind a holder is never the holder, whatever its position in
        // the file: the `->` the kernel prefixes it with lands where this shape wants
        // `FLOCK`. Asserted on its own, since above it is also outranked by line order.
        assert_eq!(
            holder_pid(
                "2: -> FLOCK  ADVISORY  WRITE 3333 fc:01:22151305 0 EOF\n",
                want
            ),
            None
        );
        // A lock held over NFS, or by an owner outside this pid namespace, names no
        // process this host can be pointed at.
        for line in [
            "5: FLOCK  ADVISORY  WRITE -1 fc:01:22151305 0 EOF\n",
            "5: FLOCK  ADVISORY  WRITE 0 fc:01:22151305 0 EOF\n",
        ] {
            assert_eq!(holder_pid(line, want), None, "{line}");
        }
        // A truncated line yields nothing rather than a wrong pid.
        assert_eq!(holder_pid("6: FLOCK  ADVISORY\n", want), None);
    }
}
