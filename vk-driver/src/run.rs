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

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use vk_core::addr::SocketAddr;

use crate::source::Source;
use crate::vmm::Vmm;

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

/// How the host re-invokes the agent's native subcommands (`fsfreeze`, `mount`,
/// `copy`) inside the guest. `/proc/self/exe` resolves, in the forked child, to the
/// running agent binary — so this works whether the agent was injected into the rootfs
/// (legacy) or booted from an initramfs and pivoted in (its on-disk path then gone).
const GUEST_AGENT: &str = "/proc/self/exe";

/// Guest mountpoint of a `--workdir` host-dir share (the live tree the command runs in).
const WORKDIR_MOUNT: &str = "/work";

/// Where a `run <image>` rootfs comes from.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
pub enum SourceMode {
    /// Pull straight from a registry (no docker daemon).
    Oci,
    /// Export from the local docker daemon (`docker export`).
    Docker,
    /// Resolve over the registry, falling back to docker for an image that is not pushed
    /// (a registry not-found); auth/network errors surface rather than silently fall back.
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
    /// Instruction cache for a Dockerfile boot: each stage's ext4 is pushed/pulled by
    /// its content key, so a repeat boot restores instead of rebuilding. A registry
    /// repo, an absolute store directory path, or `none` to disable; `None` = the
    /// builtin local store (`regserve::default_root`).
    pub cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback regserve).
    pub cache_insecure: bool,
    /// `--build-arg NAME=VALUE` overrides for the Dockerfile build.
    pub build_args: Vec<(String, String)>,
    /// host dir shared read-write into the guest (at WORKDIR_MOUNT); the command runs
    /// there, so its outputs land back on the host. `None` = no share.
    pub workdir: Option<PathBuf>,
    /// `None` uses the kernel embedded in `vk` (or the on-disk default).
    pub kernel: Option<PathBuf>,
    /// `None` uses the vk-agent embedded in `vk` (or the on-disk default).
    pub agent: Option<PathBuf>,
    pub cloud_hypervisor: PathBuf,
    /// where the rootfs comes from for an image boot (registry pull / docker export / auto)
    pub source: SourceMode,
    pub ca: Option<PathBuf>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub insecure: bool,
    pub cpus: u32,
    pub mem: String,
    pub boot_timeout_secs: u64,
    /// boot the rootfs as a cpio initramfs held in RAM instead of the default
    /// native-ext4 disk (needs --mem of roughly three times the image size)
    pub ram: bool,
    /// attach an interactive shell once the guest is up (needs a terminal)
    pub shell: bool,
    /// give the guest egress via a userspace `vk switch` (DHCP + DNS + proxy);
    /// forced on by `compose` (the services live on that switch's LAN)
    pub net: bool,
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
    /// where a `--detach` run redirects its output after detaching (default: discard)
    pub detach_log: Option<PathBuf>,
    pub command: Vec<String>,
}

pub async fn run(args: &RunArgs) -> Result<()> {
    // SAFETY: isatty has no failure mode beyond returning 0
    if args.shell && unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        bail!("--shell requires stdin and stdout to be a terminal");
    }
    let work = match &args.state_dir {
        Some(dir) => WorkDir::pinned(dir.clone())?,
        None => {
            WorkDir::create(default_scratch_base()?.join(format!("launch-{}", std::process::id())))?
        }
    };
    // Resolve the agent and kernel: an explicit flag wins, else the copy embedded
    // in `vk` (served from a memfd), else the on-disk default.
    // Held for the VM's lifetime: an embedded asset lives in a memfd whose
    // /proc/self/fd path is only valid while the fd is open.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, args.agent.as_deref())?;
    let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, args.kernel.as_deref())?;
    if !agent.is_embedded() && !agent.path.is_file() {
        bail!(
            "vk-agent not found at {} (pass --agent, or use a `vk` with it embedded)",
            agent.path.display()
        );
    }
    if !kernel.is_embedded() && !kernel.path.is_file() {
        bail!(
            "kernel not found at {} (pass --kernel, or use a `vk` with it embedded)",
            kernel.path.display()
        );
    }
    // No primary (no image, no -f, no --primary) + a compose file = compose up:
    // services only, held until ctrl-c.
    if args.image.is_empty() && args.dockerfiles.is_empty() && args.primary.is_none() {
        return compose_up(args, &work.path, &agent.path, &kernel.path).await;
    }
    build_and_boot(args, &work.path, &agent.path, &kernel.path).await
}

/// Default base for a run's launch scratch: `$XDG_CACHE_HOME/virtkit`, else
/// `~/.cache/virtkit`. Deliberately NOT `std::env::temp_dir()`: that is often a small
/// RAM-backed tmpfs (e.g. a 16 GiB `/tmp`), and a `-f` build writes its stage ext4s and the
/// assembled `root.ext4` here — a large build would exhaust the tmpfs (ENOSPC) while the
/// real disk sits idle. Cache semantics fit (transient, regenerable, removed on drop); the
/// durable instruction store lives under `$XDG_DATA_HOME` instead. `--state-dir` overrides
/// this with a caller-chosen path. The short `launch-<pid>` leaf keeps the AF_UNIX socket
/// paths created under here well within the 108-byte limit.
fn default_scratch_base() -> Result<PathBuf> {
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
            bail!("state-dir {} is in use by a live run", dir.display());
        }
        return Err(err).with_context(|| format!("locking {}", dir.display()));
    }
    Ok(f)
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

async fn build_and_boot(args: &RunArgs, work: &Path, agent: &Path, kernel: &Path) -> Result<()> {
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
    let compose_units: Vec<crate::compose::Unit> = match &args.compose {
        Some(p) => crate::compose::load(p)?,
        None => Vec::new(),
    };
    let mut image_env: Vec<(String, String)> = Vec::new();
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
    let dockerfile_ext4 = if let Some(name) = &args.primary {
        let idx = compose_units
            .iter()
            .position(|u| &u.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--primary {name:?}: no such compose service (declared: {})",
                    compose_units
                        .iter()
                        .map(|u| u.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        let unit = &compose_units[idx];
        let out = work.join("root.ext4");
        let built = build_service_image(args, unit, &out, kernel, agent)
            .with_context(|| format!("service {name}"))?;
        let cfg = crate::compose::merged_config(&built.config, unit);
        image_env = cfg.env.clone();
        primary_user = cfg.user.clone();
        primary_hostname = Some(unit.hostname.clone());
        primary_volumes = unit.volumes.clone();
        primary = Some(cfg);
        primary_idx = Some(idx);
        Some(out)
    } else if args.dockerfiles.is_empty() {
        None
    } else {
        let out = work.join("root.ext4");
        let opts = crate::build::Options {
            dockerfiles: args.dockerfiles.clone(),
            target: args.target.clone(),
            contexts: args.contexts.clone(),
            out: Some(out.clone()),
            print_plan: false,
            cloud_hypervisor: Some(args.cloud_hypervisor.clone()),
            kernel: Some(kernel.to_path_buf()),
            agent: Some(agent.to_path_buf()),
            cache_registry: args.cache_registry.clone(),
            cache_insecure: args.cache_insecure,
            build_cache: crate::build::BuildCache::default(),
            journal: false,
            tmp_tmpfs: false,
            build_args: args.build_args.clone(),
            net: args.build_net.clone(),
            require_cached: args.require_cached,
            build_jobs: None,
            debug: false,
        };
        let built = crate::build::build(&opts)?;
        primary_user = built.config.user;
        image_env = built.config.env;
        Some(out)
    };

    // 1. the rootfs source (docker export or registry pull) for an image boot, unless a
    // Dockerfile build already produced the ext4 above. The rootfs tar itself never
    // exists as a file — step 2 streams it straight into the cpio/ext4 builder.
    let source = match dockerfile_ext4 {
        None => {
            let source = resolve_source(args).await?;
            // Inherit the image's configured environment (PATH etc.) for the guest
            // command, as `docker run` does.
            image_env = source.config_env().await?;
            Some(source)
        }
        Some(_) => None,
    };
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
    let (disks, initramfs, mut cmdline): (Vec<crate::vmm::Disk>, Option<PathBuf>, String) =
        if let Some(ext4) = &dockerfile_ext4 {
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
            if let Some(mem_mib) = parse_mem_mib(&args.mem)
                && mem_mib < need_mib
            {
                bail!(
                    "the image unpacks to a {initramfs_mib} MiB initramfs, which does not fit \
                     in --mem {} — pass --mem {}G, or drop --ram to boot from a disk",
                    args.mem,
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
    let planned = plan_services(args, work, kernel, agent, &compose_units, primary_idx)?;
    // With sibling services under management, the agent exposes their control
    // plane at /run/vk/services (a FUSE bridge to the manager over vsock).
    if !planned.units.is_empty() {
        cmdline.push_str(" VIRTKIT_CTL=1");
    }

    // --host-exec: the guest agent presents /run/vk/host.sock, relayed over vsock
    // to a host-side `vk-agent serve` (spawned after boot, below).
    if args.host_exec {
        cmdline.push_str(&format!(" VIRTKIT_HOST_EXEC_PORT={HOST_EXEC_PORT}"));
    }

    // Networking: a userspace `vk switch` over vsock gives the guest egress (the agent
    // forks a tap bridged to it and takes the static address from the cmdline fragment).
    // With services it also pre-listens on their sockets and answers their aliases.
    let mut switch = if args.net {
        let (child, frag) = spawn_vm_switch(
            &vsock,
            work,
            NET_VSOCK_PORT,
            &[],
            &[],
            &planned.listen,
            &planned.hosts,
        )
        .await?;
        cmdline.push_str(&frag);
        Some(child)
    } else {
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
        });
    }
    // A --primary primary gets its compose volumes, and any primary its `--volume`
    // flags, exactly like a sibling unit would: bind mounts over virtiofs.
    // Persistent state (a dev VM's ~/.vscode-server, say) is whatever binds to a
    // host dir — the VM itself stays throwaway.
    for (i, vol) in primary_volumes.iter().chain(&args.volumes).enumerate() {
        let tag = format!("vol{i}");
        let sock = work.join(format!("vfsd-{tag}.sock"));
        if !crate::vmm::libkrun_selected() {
            virtiofsds.push(crate::spawn::spawn_virtiofsd(
                &sock,
                &vol.host,
                vol.read_only,
                &[],
                &[],
            )?);
        }
        if !virtiofs.is_empty() {
            virtiofs.push(',');
        }
        virtiofs.push_str(&format!("{tag}:{}", vol.guest));
        shares.push(crate::vmm::FsShare {
            tag,
            socket: sock,
            host_dir: vol.host.clone(),
            read_only: vol.read_only,
        });
    }
    if !virtiofs.is_empty() {
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS={virtiofs}"));
    }
    // In-guest symlinks, created by the agent after the mounts — the single-file
    // share escape hatch (virtiofs shares directories only); a dangling source is
    // skipped guest-side.
    if !args.symlinks.is_empty() {
        let spec: Vec<String> = args
            .symlinks
            .iter()
            .map(|(src, dest)| format!("{src}:{dest}"))
            .collect();
        cmdline.push_str(&format!(" VIRTKIT_SYMLINKS={}", spec.join(",")));
    }
    let shared_mem = !shares.is_empty();

    // 3. boot
    let console = work.join("console.log");
    let vmm = crate::vmm::selected(&args.cloud_hypervisor);
    let addr = crate::vmm::exec_addr(&vsock, VSOCK_PORT);
    println!(
        "virtkit: booting {} (cpus={}, mem={})",
        vmm.name(),
        args.cpus,
        args.mem
    );
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
    let spec = crate::vmm::VmSpec {
        kernel: kernel.to_path_buf(),
        cmdline,
        disks,
        initramfs,
        shares,
        vsock_cid: 3,
        vsock_socket: vsock.clone(),
        vsock_ports,
        cpus: args.cpus,
        mem: args.mem.clone(),
        shared_mem,
        net: crate::vmm::Net::None,
        balloon: false,
        serial_log: console.clone(),
        api_socket: None,
        pass_fds,
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

    // The ProxyCommand splices ssh's stdio onto the guest's vsock ssh port, so
    // the hostname after `user@` is only a known_hosts label. The host key is
    // ephemeral (fresh per boot, reached over a private channel), hence the
    // relaxed checking options.
    if args.ssh {
        // vsock-auto: the ProxyCommand picks the best path itself — the per-port
        // listener when the backend has one, else the CONNECT handshake.
        let target = format!("vsock-auto://{}:{SSH_VSOCK_PORT}", vsock.display());
        let exe = std::env::current_exe().context("locating the virtkit binary")?;
        println!(
            "virtkit: ssh: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ProxyCommand=\"'{}' connect --to '{target}'\" {}@vk-run",
            exe.display(),
            args.ssh_user
        );
    }

    // Host side of the SSH-agent forward: the guest dials vsock port SSH_AGENT_VSOCK_PORT,
    // surfaced by cloud-hypervisor as <vsock.sock>_<port>. With --ssh-host a filtering proxy
    // exposes only the chosen keys; a bare --ssh-agent splices the whole agent through.
    let mut ssh_forward = match &ssh {
        Some(s) if s.allow_pub.is_empty() && s.guest_config.is_none() => {
            Some(spawn_ssh_agent_forward(&vsock, &s.upstream, work)?)
        }
        Some(s) => Some(spawn_ssh_agent_proxy(
            &vsock,
            &s.upstream,
            &s.allow_pub,
            work,
        )?),
        None => None,
    };
    let ssh_config = ssh.and_then(|s| s.guest_config);

    // Host side of the host-exec channel: a `vk-agent serve` on the bridged
    // per-port socket the guest's /run/vk/host.sock forwarder dials. cwd is the
    // --workdir (else our own), so a relative `exec --dir` resolves against the
    // shared tree; the wrapper (if any) enforces what may run.
    let mut host_exec_serve = if args.host_exec {
        Some(spawn_host_exec_serve(&vsock, agent, args, work)?)
    } else {
        None
    };

    // With a --primary primary and no trailing command, the service's own
    // entrypoint+cmd runs — `docker compose run <svc>` semantics.
    let fallback_argv = primary.map(|c| c.argv()).unwrap_or_default();
    let result = drive(
        &mut ch,
        &addr,
        &console,
        args,
        ssh_config.as_deref(),
        &image_env,
        &fallback_argv,
    )
    .await;
    for mut f in ssh_forward.take().into_iter().chain(host_exec_serve.take()) {
        let _ = f.kill();
        let _ = f.wait();
    }
    let _ = ch.kill();
    let _ = ch.wait();
    if let Some(mgr) = &manager {
        mgr.stop_all();
    }
    for mut child in virtiofsds.drain(..).chain(switch.take()) {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// Every declared compose unit, materialized and addressed, plus which ones
/// boot eagerly and what the switch must serve for them.
struct PlannedServices {
    /// (unit, runtime dir) for the manager — the `--primary` primary excluded
    /// (it boots as the run VM, not as a sibling)
    units: Vec<(crate::units::Provisioned, PathBuf)>,
    /// names to boot eagerly: the profile-enabled set, or the primary's
    /// dependency closure
    start: Vec<String>,
    /// per-unit switch sockets (up or down — an on-demand start dials a
    /// listening LAN)
    listen: Vec<PathBuf>,
    /// alias -> ip for the gateway resolver
    hosts: Vec<(String, String)>,
}

/// Materialize EVERY declared unit into the work dir — like the `-f` build
/// itself, warmth comes from the instruction cache — so the manager can start a
/// profiled-down unit on demand later; only `start` boots eagerly.
fn plan_services(
    args: &RunArgs,
    work: &Path,
    kernel: &Path,
    agent: &Path,
    units: &[crate::compose::Unit],
    primary_idx: Option<usize>,
) -> Result<PlannedServices> {
    let mut planned = PlannedServices {
        units: Vec::new(),
        start: Vec::new(),
        listen: Vec::new(),
        hosts: Vec::new(),
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
    let mut slot = 0u32;
    for &i in &order {
        // the primary is the run VM itself, not a sibling unit
        if Some(i) == primary_idx {
            continue;
        }
        let unit = &units[i];
        let dir = work.join(format!("svc-{}", unit.name));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let ext4 = dir.join("image.ext4");
        let built = build_service_image(args, unit, &ext4, kernel, agent)
            .with_context(|| format!("service {}", unit.name))?;
        let config = crate::compose::merged_config(&built.config, unit);
        let ip = crate::units::nth_static_ip(gw, prefix, slot)?;
        planned
            .listen
            .push(dir.join(format!("vsock.sock_{NET_VSOCK_PORT}")));
        planned
            .hosts
            .push((unit.name.to_ascii_lowercase(), ip.to_string()));
        if unit.hostname != unit.name {
            planned
                .hosts
                .push((unit.hostname.to_ascii_lowercase(), ip.to_string()));
        }
        planned.units.push((
            crate::units::Provisioned {
                name: unit.name.clone(),
                hostname: unit.hostname.clone(),
                ext4,
                ip: format!("{ip}/{prefix}"),
                cid: crate::units::FIRST_SERVICE_CID + slot,
                config,
                volumes: unit.volumes.clone(),
            },
            dir,
        ));
        if on[i] {
            planned.start.push(unit.name.clone());
        }
        slot += 1;
    }
    Ok(planned)
}

/// `vk run --compose` with no primary — compose up: boot the enabled services
/// on the run LAN and hold until ctrl-c; everything dies with this process.
async fn compose_up(args: &RunArgs, work: &Path, agent: &Path, kernel: &Path) -> Result<()> {
    let compose = args
        .compose
        .as_ref()
        .expect("compose_up requires --compose");
    let units = crate::compose::load(compose)?;
    if units.is_empty() {
        bail!("{} declares no services", compose.display());
    }
    let planned = plan_services(args, work, kernel, agent, &units, None)?;

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
    )
    .await?;

    let (gw, prefix, _) = crate::net::switch_addrs(RUN_SUBNET)?;
    let mgr = std::sync::Arc::new(crate::manager::Manager::new(
        kernel.to_path_buf(),
        args.cloud_hypervisor.clone(),
        NET_VSOCK_PORT,
        gw,
        agent.to_path_buf(),
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
    let _ = switch.kill();
    let _ = switch.wait();
    Ok(())
}

/// Materialize one compose service's clean image into the work dir: a `build:`
/// unit through the builder directly, an `image:` unit as the synthetic
/// single-`FROM` plan — both warmed by the instruction cache (a pulled base is
/// digest-keyed, so a repeat run restores instead of re-pulling).
fn build_service_image(
    args: &RunArgs,
    unit: &crate::compose::Unit,
    out: &Path,
    kernel: &Path,
    agent: &Path,
) -> Result<crate::build::Built> {
    let mut opts = crate::build::Options {
        dockerfiles: Vec::new(),
        target: None,
        contexts: Vec::new(),
        out: Some(out.to_path_buf()),
        print_plan: false,
        cloud_hypervisor: Some(args.cloud_hypervisor.clone()),
        kernel: Some(kernel.to_path_buf()),
        agent: Some(agent.to_path_buf()),
        cache_registry: args.cache_registry.clone(),
        cache_insecure: args.cache_insecure,
        build_cache: crate::build::BuildCache::default(),
        journal: false,
        tmp_tmpfs: false,
        build_args: args.build_args.clone(),
        net: args.build_net.clone(),
        require_cached: args.require_cached,
        build_jobs: None,
        debug: false,
    };
    match &unit.source {
        crate::compose::Source::Build {
            dockerfiles,
            context,
            target,
            args: unit_args,
        } => {
            opts.dockerfiles = dockerfiles.clone();
            // compose semantics: one context for all the service's files.
            opts.contexts = vec![context.clone(); dockerfiles.len()];
            opts.target = target.clone();
            opts.build_args.extend(unit_args.iter().cloned());
            crate::build::build(&opts)
        }
        crate::compose::Source::Image(image) => {
            crate::build::build_inputs(vec![crate::build::image_plan_input(image)?], &opts)
        }
    }
}

/// Spawn the host side of the SSH-agent forward: `vk forward` binds the VMM's per-port
/// vsock socket (`<vsock.sock>_<port>`) and splices every guest connection to the host's
/// `$SSH_AUTH_SOCK`. Long-lived for the VM's lifetime; the caller kills it on teardown.
fn spawn_ssh_agent_forward(vsock: &Path, host_sock: &OsStr, work: &Path) -> Result<Child> {
    let mut listen = vsock.to_path_buf().into_os_string();
    listen.push(format!("_{SSH_AGENT_VSOCK_PORT}"));
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let log = std::fs::File::create(work.join("ssh-agent-forward.log"))
        .context("creating the ssh-agent forward log")?;
    let mut cmd = Command::new(exe);
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
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let log = std::fs::File::create(work.join("ssh-agent-forward.log"))
        .context("creating the ssh-agent forward log")?;
    let mut cmd = Command::new(exe);
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

async fn drive(
    ch: &mut Child,
    addr: &SocketAddr,
    console: &Path,
    args: &RunArgs,
    ssh_config: Option<&str>,
    image_env: &[(String, String)],
    fallback_argv: &[String],
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.boot_timeout_secs);
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
    let user_script = user_script(if args.command.is_empty() {
        fallback_argv
    } else {
        &args.command
    });
    // A `--workdir` share mounts the live tree at WORKDIR_MOUNT; run the command there so it
    // sees the shared files and writes its outputs back to the host.
    let body = match &args.workdir {
        Some(_) => format!("cd {WORKDIR_MOUNT} && {user_script}"),
        None => user_script,
    };
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
    let command = vec!["sh".into(), "-c".into(), script];
    let result = crate::executor::exec_script(
        addr,
        &command,
        Vec::new(),
        None,
        &crate::executor::OutputSink::Inherit,
        None,
    )
    .await
    .context("running the command in the guest")?;
    match result.code {
        Some(0) | None => Ok(()),
        Some(c) => bail!("guest command exited {c}"),
    }
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

/// Attach an interactive shell to the guest: a remote PTY wired to the local
/// terminal (raw mode), sized to it. Returns when the shell exits, whatever its
/// status — a shell that quits non-zero is not a launch failure.
async fn run_shell(addr: &SocketAddr) -> Result<()> {
    use vk_core::messages::{CmdExec, RunMode, Tty};
    let (rows, cols) = vk_core::pty::get_winsize(0).unwrap_or((24, 80));
    let (stream, sink) = vk_core::net::connect(addr)
        .await
        .context("connecting to the VM's vk-agent")?;
    let exec = CmdExec {
        name: "sh".into(),
        args: vec!["-i".into()],
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
    vk_core::exec::client::client_run_tty(stream, sink, exec)
        .await
        .context("interactive guest shell")?;
    Ok(())
}

fn spawn_vmm(vmm: &dyn Vmm, spec: &crate::vmm::VmSpec) -> Result<Child> {
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
async fn spawn_vm_switch(
    vsock: &Path,
    work: &Path,
    net_port: u32,
    allow_ip: &[String],
    allow_name: &[String],
    extra_listen: &[PathBuf],
    hosts: &[(String, String)],
) -> Result<(Child, String)> {
    let (gw, prefix, guest_ip) = crate::net::switch_addrs(RUN_SUBNET)?;
    let mut listen = vsock.to_path_buf().into_os_string();
    listen.push(format!("_{net_port}"));
    let mut all_listen = vec![PathBuf::from(listen)];
    all_listen.extend(extra_listen.iter().cloned());
    let child = crate::switch::spawn(&crate::switch::Spawn {
        listen: all_listen,
        gateway: gw,
        prefix,
        hosts: hosts.to_vec(),
        allow_ip: allow_ip.to_vec(),
        allow_name: allow_name.to_vec(),
        log: work.join("switch.log"),
    })?;
    let frag = format!(
        " VIRTKIT_NET_PORT={net_port} VIRTKIT_VM_IP={guest_ip}/{prefix} \
         VIRTKIT_VM_GW={gw} VIRTKIT_VM_DNS={gw}"
    );
    Ok((child, frag))
}

/// Boot a stage guest on `image` (a rw qcow2, written in place) and wait for the in-guest
/// agent. Unless `net` is `None`, a `vk switch` gives egress (DHCP + DNS + transparent
/// proxy), restricted to `net`'s allowlist if it has one.
#[allow(clippy::too_many_arguments)]
/// Lightweight phase timing for the cache-push path, enabled with `VIRTKIT_TIMING=1`.
/// Emits one line per phase; summing them across a build sizes how much of cold-cache-on
/// is reclaimable by moving work off the critical path (the async-push plan).
pub(crate) fn tlog(phase: &str, started: Instant) {
    if std::env::var_os("VIRTKIT_TIMING").is_some() {
        eprintln!(
            "virtkit-timing: {phase} {} ms",
            started.elapsed().as_millis()
        );
    }
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
    cancel: Option<CancellationToken>,
) -> Result<VmSession> {
    let stem = image.file_stem().and_then(|s| s.to_str()).unwrap_or("disk");
    let work = std::env::temp_dir().join(format!("virtkit-session-{}-{stem}", std::process::id()));
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    // The agent boots as PID 1 from a minimal initramfs (just `/init`), then pivots into
    // the ext4 root below — so the agent is never written into the built image. With
    // libkrun it is an unlinked scratch fd: `_cpio` keeps it open until the VMM child
    // (which inherits the fd via pass_fds below) has spawned, i.e. past spawn_vmm.
    let mut pass_fds: Vec<i32> = Vec::new();
    let mut _cpio: Option<crate::scratch::ScratchFile> = None;
    let cpio = if crate::vmm::libkrun_selected() {
        let s = crate::scratch::scratch(&work, "initramfs.cpio")?;
        let path = s.path.clone();
        pass_fds.push(s.fd());
        _cpio = Some(s);
        path
    } else {
        work.join("initramfs.cpio")
    };
    crate::initramfs::build_agent_initramfs(agent, &cpio)?;
    // Boot the stage's rw qcow2 image directly: it is a CoW overlay over its backing (the
    // base ext4 or the parent stage), so the guest's writes accumulate into it and it
    // becomes the stage's result — no separate boot overlay, no commit. (A raw-rw disk
    // does not present as /dev/vda, which is why every stage image is a qcow2.)
    let mut disks: Vec<crate::vmm::Disk> = vec![crate::vmm::Disk::overlay(image.to_path_buf())];
    // Source stages for COPY --from / RUN --mount=from, attached read-only as the next
    // virtio-blk disks (vdb, vdc, … in order) for the guest to mount and read. A forked
    // source is a qcow2 over its parent (its backing chain is resolved); a base source is
    // a plain raw ext4.
    for src in sources {
        disks.push(crate::vmm::Disk {
            path: src.clone(),
            qcow2: disk_format(src) == "qcow2",
            readonly: true,
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
    let spec = crate::vmm::VmSpec {
        kernel: kernel.to_path_buf(),
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
        balloon: false,
        serial_log: console.clone(),
        api_socket: None,
        pass_fds,
    };
    let vmm = crate::vmm::selected(cloud_hypervisor);
    let addr = crate::vmm::exec_addr(&vsock, VSOCK_PORT);
    let mut ch = spawn_vmm(vmm.as_ref(), &spec)?;
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
    Ok(VmSession {
        ch,
        addr,
        image: image.to_path_buf(),
        switch,
        virtiofsd,
        work,
        scratch_dev,
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
    pub(crate) async fn capture(&self, out: &Path) -> Result<()> {
        let t = Instant::now();
        let frozen = self.freeze().await;
        let copied = std::fs::copy(&self.image, out);
        self.thaw(frozen).await;
        copied.with_context(|| format!("copying {} -> {}", self.image.display(), out.display()))?;
        tlog("snap.capture", t);
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

    /// The live stage overlay (the booted rw qcow2). During a freeze it is a stable point-in-time
    /// source; the build checkpoint reads its allocated extents directly from it.
    pub(crate) fn image(&self) -> &Path {
        &self.image
    }

    /// Shut the guest down cleanly: drop ephemeral mountpoints and flush the root fs to its
    /// block device, then kill the VM. The stage image is the booted disk, so its writes are
    /// already persisted in place — there is nothing to commit.
    pub(crate) async fn finish(mut self) -> Result<()> {
        // `cleanup` removes the agent-created ephemeral mountpoints/stubs (so they do not
        // litter the image) and then syncs — all native, so it works on a shell-less
        // `FROM scratch` stage. Fall back to a native fsfreeze, then a shell `sync`, if an
        // older agent lacks cleanup. The guest is killed right after, so no thaw is needed.
        let quiesced = self.guest_ok(&[GUEST_AGENT, "cleanup"]).await
            || self.guest_ok(&[GUEST_AGENT, "fsfreeze", "-f", "/"]).await;
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
        let _ = self.ch.kill();
        let _ = self.ch.wait();
        for c in [self.switch.as_mut(), self.virtiofsd.as_mut()]
            .into_iter()
            .flatten()
        {
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
        for c in [self.switch.as_mut(), self.virtiofsd.as_mut()]
            .into_iter()
            .flatten()
        {
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
                None,
                None,
                None,
                None,
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
            api_socket: None,
            pass_fds: vec![medium.fd()],
        };
        let mut child = spawn_vmm(&CatVmm, &spec).unwrap();
        assert!(child.wait().unwrap().success());
        let out = std::fs::read(spec.serial_log.with_extension("vmm.log")).unwrap();
        assert_eq!(out, b"boot medium");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
