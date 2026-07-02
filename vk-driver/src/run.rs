//! `vk run` — dev: boot a generic OCI image as a microVM directly,
//! no gitlab-runner. The rootfs comes from a `source::Source` (a registry pull or
//! `docker export`, chosen by `--source`); it is turned into a cpio initramfs (RAM) or a
//! native ext4 disk, with the static virtkit-agent injected as PID 1; and booted on
//! an all-built-in kernel (the pinned `vmlinux`) — no modules, and no initrd
//! for the disk path (virtio-blk + ext4 are built in). docker/cloud-hypervisor
//! aside (docker only with `--source docker`/`auto`), nothing else is needed.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use vk_core::addr::SocketAddr;

use crate::source::Source;
use crate::vmm::Vmm;

const VSOCK_PORT: u32 = 4444;
/// vsock port the guest SSH-agent forwarder dials; the host splices it to `$SSH_AUTH_SOCK`.
pub(crate) const SSH_AGENT_VSOCK_PORT: u32 = 2223;
/// vsock port the guest's tap bridge dials to reach the userspace switch.
const NET_VSOCK_PORT: u32 = 1024;

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
    /// `cache_registry`) the target into an ext4 and boot it — no explicit `--out` ext4.
    pub dockerfile: Option<PathBuf>,
    /// Target stage to boot (AS name or index; default: the last stage), with `dockerfile`.
    pub target: Option<String>,
    /// Build context for the Dockerfile's `COPY` (default: the Dockerfile's directory).
    pub context: Option<PathBuf>,
    /// Instruction-cache registry: the Dockerfile build pushes/pulls each stage's ext4
    /// there by its content key, so a repeat boot restores the image instead of rebuilding.
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
    /// give the guest egress via a userspace `vk switch` (DHCP + DNS + proxy)
    pub net: bool,
    /// forward the host SSH agent into the guest (keys never enter the guest)
    pub ssh_agent: bool,
    /// expose only these ~/.ssh/config host aliases (filtered agent + injected config);
    /// implies SSH-agent forwarding
    pub ssh_hosts: Vec<String>,
    pub command: Vec<String>,
}

pub async fn run(args: &RunArgs) -> Result<()> {
    // SAFETY: isatty has no failure mode beyond returning 0
    if args.shell && unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        bail!("--shell requires stdin and stdout to be a terminal");
    }
    let work = std::env::temp_dir().join(format!("virtkit-launch-{}", std::process::id()));
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    // Resolve the agent and kernel: an explicit flag wins, else the copy embedded
    // in `vk` (served from a memfd), else the on-disk default.
    let result = async {
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
        build_and_boot(args, &work, &agent.path, &kernel.path).await
    }
    .await;
    let _ = std::fs::remove_dir_all(&work);
    result
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
    let mut image_env: Vec<(String, String)> = Vec::new();
    let dockerfile_ext4 = match &args.dockerfile {
        Some(file) => {
            let out = work.join("root.ext4");
            let opts = crate::build::Options {
                dockerfile: file.clone(),
                target: args.target.clone(),
                context: args.context.clone(),
                out: Some(out.clone()),
                print_plan: false,
                microvm: true,
                cloud_hypervisor: Some(args.cloud_hypervisor.clone()),
                kernel: Some(kernel.to_path_buf()),
                agent: Some(agent.to_path_buf()),
                cache_registry: args.cache_registry.clone(),
                cache_insecure: args.cache_insecure,
                journal: false,
                build_args: args.build_args.clone(),
            };
            image_env = crate::build::build(&opts)?.env;
            Some(out)
        }
        None => None,
    };

    // 1. fetch the rootfs (docker export or registry pull) as a tar, unless a Dockerfile
    // build already produced the ext4 above.
    let rootfs_tar = work.join("rootfs.tar");
    if dockerfile_ext4.is_none() {
        let source = resolve_source(args).await?;
        // Inherit the image's configured environment (PATH etc.) for the guest command,
        // as `docker run` does.
        image_env = source.config_env().await?;
        source.to_tar(&rootfs_tar).await?;
    }

    // 2. assemble the boot medium (virtkit-agent injected as PID 1).
    let (disks, initramfs, mut cmdline): (Vec<crate::vmm::Disk>, Option<PathBuf>, String) =
        if let Some(ext4) = &dockerfile_ext4 {
            // A Dockerfile build exports a *clean* ext4 (no agent baked in). Boot it the way
            // the builder boots its own stages: a minimal initramfs holds the agent as `/init`,
            // which pivots into the ext4 at /dev/vda — so the booted image stays byte-clean.
            let cpio = work.join("initramfs.cpio");
            crate::initramfs::build_agent_initramfs(agent, &cpio)?;
            // throwaway rw qcow2 overlay over the ro raw ext4 (rw raw errors on tmpfs)
            let overlay = work.join("overlay.qcow2");
            crate::qcow2::create_overlay(&overlay, ext4)?;
            (
                vec![crate::vmm::Disk::overlay(overlay)],
                Some(cpio),
                format!(
                    "console=ttyS0 rdinit=/init VIRTKIT_PIVOT=/dev/vda \
                     VIRTKIT_HOSTNAME=vm VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
                ),
            )
        } else if !args.ram {
            println!("virtkit: building ext4 rootfs");
            let rootfs = work.join("root.ext4");
            crate::ext4::build_from_tar(&rootfs_tar, agent, &rootfs)?;
            // throwaway rw qcow2 overlay over the ro raw ext4 (rw raw errors on tmpfs)
            let overlay = work.join("overlay.qcow2");
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
            let cpio = work.join("initramfs.cpio");
            crate::initramfs::build_initramfs(&rootfs_tar, agent, &cpio)?;
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

    // Networking: a userspace `vk switch` over vsock gives the guest egress (the agent
    // forks a tap bridged to it and takes the static address from the cmdline fragment).
    let mut switch = if args.net {
        let (child, frag) = spawn_vm_switch(&vsock, work, NET_VSOCK_PORT).await?;
        cmdline.push_str(&frag);
        Some(child)
    } else {
        None
    };

    // Working directory: share a host dir read-write over virtiofs at WORKDIR_MOUNT (no uid
    // map, like the fleet dev VM — virtiofsd's `--sandbox=none` writes back as the host
    // user), so the guest command reads/writes the live tree and its outputs land on the
    // host. The command then runs with its cwd there (see `drive`). virtio-fs needs shared
    // guest memory, so `mem` gains `shared=on`.
    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    let mut virtiofsd: Option<Child> = None;
    let shared_mem = if let Some(host_dir) = &args.workdir {
        let sock = work.join("workdir.fs.sock");
        // libkrun mounts host_dir directly (built-in virtio-fs); only cloud-hypervisor
        // needs the external virtiofsd on `sock`.
        if !crate::vmm::libkrun_selected() {
            virtiofsd = Some(crate::fleet::spawn_virtiofsd(
                &sock,
                host_dir,
                false,
                &[],
                &[],
            )?);
        }
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS=work:{WORKDIR_MOUNT}"));
        shares.push(crate::vmm::FsShare {
            tag: "work".into(),
            socket: sock,
            host_dir: host_dir.clone(),
            read_only: false,
        });
        true
    } else {
        false
    };

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
    };
    let mut ch = match spawn_vmm(vmm.as_ref(), &spec) {
        Ok(ch) => ch,
        // The --net switch and --workdir virtiofsd are already spawned; kill them so a
        // failed boot does not leak host-side children (a leaked `vk virtiofsd` would,
        // e.g., hold this binary's file busy for the next build).
        Err(e) => {
            for mut child in [switch.take(), virtiofsd.take()].into_iter().flatten() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(e);
        }
    };

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

    let result = drive(
        &mut ch,
        &addr,
        &console,
        args,
        ssh_config.as_deref(),
        &image_env,
    )
    .await;
    if let Some(mut f) = ssh_forward.take() {
        let _ = f.kill();
        let _ = f.wait();
    }
    let _ = ch.kill();
    let _ = ch.wait();
    for mut child in [switch.take(), virtiofsd.take()].into_iter().flatten() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
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
    crate::fleet::spawn_tied(cmd).context("spawning the ssh-agent forward")
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
    crate::fleet::spawn_tied(cmd).context("spawning the ssh-agent proxy")
}

/// Wait for the in-guest virtkit-agent, run the command, relay its output. `ssh_config`, if
/// set, is written to the guest's `~/.ssh/config` once it is ready (the `--ssh-host` stanzas).
/// Single-quote a value for a `/bin/sh` `export` (wrap in `'…'`, escaping embedded `'`).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

async fn drive(
    ch: &mut Child,
    addr: &SocketAddr,
    console: &Path,
    args: &RunArgs,
    ssh_config: Option<&str>,
    image_env: &[(String, String)],
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
    if args.shell {
        return run_shell(addr).await;
    }
    let user_script = if args.command.is_empty() {
        "echo PID1=$(cat /proc/1/comm); id; uname -a; cat /etc/os-release | head -1".to_string()
    } else {
        args.command.join(" ")
    };
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
    let result = crate::executor::exec_script(addr, &command, Vec::new(), None)
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
    let r = crate::executor::exec_script(addr, &cmd, config.as_bytes().to_vec(), None)
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
    // An embedded kernel is a CLOEXEC memfd addressed as /proc/self/fd/<n> (so idle
    // helpers never inherit it). Hand it to the VMM alone by clearing CLOEXEC on that fd
    // in the forked child, so it survives exec and the VMM can open the path.
    if let Some(fd) = spec
        .kernel
        .to_str()
        .and_then(|s| s.strip_prefix("/proc/self/fd/"))
        .and_then(|n| n.parse::<std::os::unix::io::RawFd>().ok())
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec runs in the forked child before exec; fcntl(F_SETFD) is
        // async-signal-safe. F_SETFD 0 clears FD_CLOEXEC (the only fd flag).
        unsafe {
            cmd.pre_exec(move || match libc::fcntl(fd, libc::F_SETFD, 0) {
                -1 => Err(std::io::Error::last_os_error()),
                _ => Ok(()),
            });
        }
    }
    // Self-reap the VM if virtkit dies before teardown — a leaked VMM is a whole
    // running guest, not just an idle helper (spawn_tied).
    crate::fleet::spawn_tied(cmd).context("spawning the VMM")
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
}

/// Guest mountpoint of the build-context virtiofs share (for `COPY` from the context).
pub(crate) const CONTEXT_MOUNT: &str = "/run/virtkit-context";

/// Spawn a `vk switch` giving one VM a userspace LAN + egress over `vsock` (DHCP +
/// DNS + transparent proxy, unrestricted). Returns the switch child and the cmdline
/// fragment the guest agent needs to bring up its tap. Waits for the switch to bind.
async fn spawn_vm_switch(vsock: &Path, work: &Path, net_port: u32) -> Result<(Child, String)> {
    let (gw, prefix, guest_ip) = crate::net::switch_addrs("192.168.127.0/24")?;
    let mut listen = vsock.to_path_buf().into_os_string();
    listen.push(format!("_{net_port}"));
    let listen = PathBuf::from(listen);
    let _ = std::fs::remove_file(&listen);
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let swlog = std::fs::File::create(work.join("switch.log"))?;
    let mut cmd = Command::new(&exe);
    cmd.arg("switch")
        .arg("--listen")
        .arg(&listen)
        .arg("--gateway")
        .arg(gw.to_string())
        .arg("--prefix")
        .arg(prefix.to_string())
        .stdin(Stdio::null())
        .stdout(swlog.try_clone()?)
        .stderr(swlog);
    // self-reap if virtkit dies before teardown (spawn_tied)
    let mut child = crate::fleet::spawn_tied(cmd)
        .with_context(|| format!("spawning {} switch", exe.display()))?;
    let dl = Instant::now() + Duration::from_secs(5);
    while !listen.exists() {
        if Instant::now() >= dl {
            let _ = child.kill();
            let _ = child.wait();
            bail!("vk switch did not bind {}", listen.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let frag = format!(
        " VIRTKIT_NET_PORT={net_port} VIRTKIT_VM_IP={guest_ip}/{prefix} \
         VIRTKIT_VM_GW={gw} VIRTKIT_VM_DNS={gw}"
    );
    Ok((child, frag))
}

/// Boot a stage guest on `image` (a rw qcow2, written in place) and wait for the in-guest
/// agent. With `net`, a `vk switch` gives egress (DHCP + DNS + transparent proxy).
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn boot_session(
    cloud_hypervisor: &Path,
    kernel: &Path,
    agent: &Path,
    image: &Path,
    net: bool,
    cpus: u32,
    mem: &str,
    boot_timeout_secs: u64,
    sources: &[PathBuf],
    context: Option<&Path>,
) -> Result<VmSession> {
    let stem = image.file_stem().and_then(|s| s.to_str()).unwrap_or("disk");
    let work = std::env::temp_dir().join(format!("virtkit-session-{}-{stem}", std::process::id()));
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    // The agent boots as PID 1 from a minimal initramfs (just `/init`), then pivots into
    // the ext4 root below — so the agent is never written into the built image.
    let cpio = work.join("initramfs.cpio");
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
    // The kernel runs the initramfs `/init` (the agent); it then pivots into the ext4
    // named by VIRTKIT_PIVOT. No `init=`/`root=` for the kernel to mount — the agent does.
    let mut cmdline = format!(
        "console=ttyS0 rdinit=/init VIRTKIT_PIVOT=/dev/vda \
         VIRTKIT_HOSTNAME=vm VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
    );
    let vsock = work.join("vsock.sock");
    let console = work.join("console.log");

    // Build context for COPY from the context: served read-only over virtiofs and
    // mounted by the agent at CONTEXT_MOUNT (it reads VIRTKIT_VIRTIOFS at boot).
    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    let mut virtiofsd: Option<Child> = None;
    if let Some(ctx) = context {
        let sock = work.join("context.fs.sock");
        if !crate::vmm::libkrun_selected() {
            virtiofsd = Some(crate::fleet::spawn_virtiofsd(&sock, ctx, true, &[], &[])?);
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
    if net {
        let (child, frag) = spawn_vm_switch(&vsock, &work, NET_VSOCK_PORT).await?;
        switch = Some(child);
        cmdline.push_str(&frag);
    }

    let mut vsock_ports = vec![crate::vmm::VsockPort::exec(&vsock, VSOCK_PORT)];
    if net {
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
    })
}

impl VmSession {
    /// Run `command` (optionally as `user`) in the live guest; returns its exit code.
    pub(crate) async fn exec(&self, command: &[String], user: Option<String>) -> Result<i32> {
        let r = crate::executor::exec_script(&self.addr, command, Vec::new(), user)
            .await
            .context("running the command in the guest")?;
        Ok(r.code.unwrap_or(0))
    }

    /// Run a guest command (as root) and report whether it exited 0 — for best-effort
    /// quiesce helpers where a missing binary or non-zero exit just means "fall back".
    async fn guest_ok(&self, argv: &[&str]) -> bool {
        let cmd: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        matches!(
            crate::executor::exec_script(&self.addr, &cmd, Vec::new(), None).await,
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
        let frozen = self.guest_ok(&[GUEST_AGENT, "fsfreeze", "-f", "/"]).await;
        if !frozen {
            let _ =
                crate::executor::exec_script(&self.addr, &["sync".to_string()], Vec::new(), None)
                    .await;
        }
        let copied = std::fs::copy(&self.image, out);
        if frozen {
            let _ = self.guest_ok(&[GUEST_AGENT, "fsfreeze", "-u", "/"]).await;
        }
        copied.with_context(|| format!("copying {} -> {}", self.image.display(), out.display()))?;
        tlog("snap.capture", t);
        Ok(())
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
            let _ =
                crate::executor::exec_script(&self.addr, &["sync".to_string()], Vec::new(), None)
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
                false,
                1,
                "1G",
                120,
                &[data],
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
            assert_eq!(s.exec(&mount, None).await.unwrap(), 0, "agent mount failed");
            let read = [
                "sh".to_string(),
                "-c".into(),
                "grep -q MARKER-FROM-VDB /mnt/src/payload.txt".into(),
            ];
            assert_eq!(
                s.exec(&read, None).await.unwrap(),
                0,
                "reading source failed"
            );
            s.finish().await.unwrap();
        });
    }
}
