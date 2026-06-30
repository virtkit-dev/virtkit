//! `virtkit launch` — dev: boot a generic OCI image as a microVM directly,
//! no gitlab-runner. The rootfs comes from a `source::Source` (docker export or
//! a registry pull, `--oci`); it is turned into a cpio initramfs (RAM) or a
//! native ext4 disk, with the static virtkit-agent injected as PID 1; and booted on
//! an all-built-in kernel (the pinned `vmlinux`) — no modules, and no initrd
//! for the disk path (virtio-blk + ext4 are built in). docker/cloud-hypervisor
//! aside (and docker only without `--oci`), nothing else is needed.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use virtkit_agent::addr::SocketAddr;

use crate::source::Source;

const VSOCK_PORT: u32 = 4444;
/// vsock port the guest tap bridge dials to reach the userspace switch.
const NET_VSOCK_PORT: u32 = 1024;
/// How the host re-invokes the agent's native helpers inside the guest: /proc/self/exe
/// is the running agent in the forked child, present even after the initramfs pivot.
const GUEST_AGENT: &str = "/proc/self/exe";

pub struct RunArgs {
    pub image: String,
    pub kernel: PathBuf,
    pub agent: PathBuf,
    pub cloud_hypervisor: PathBuf,
    /// pull from a registry (oci.rs) instead of `docker export`
    pub oci: bool,
    pub ca: Option<PathBuf>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub insecure: bool,
    pub cpus: u32,
    pub mem: String,
    pub boot_timeout_secs: u64,
    /// boot from a native ext4 disk instead of a cpio initramfs
    pub disk: bool,
    /// attach an interactive shell once the guest is up (needs a terminal)
    pub shell: bool,
    pub command: Vec<String>,
}

pub async fn run(args: &RunArgs) -> Result<()> {
    if !args.agent.is_file() {
        bail!(
            "virtkit-agent not found at {} (build it: ./build.sh)",
            args.agent.display()
        );
    }
    if !args.kernel.is_file() {
        bail!(
            "kernel not found at {} (the pinned guest vmlinux)",
            args.kernel.display()
        );
    }
    // SAFETY: isatty has no failure mode beyond returning 0
    if args.shell && unsafe { libc::isatty(0) != 1 || libc::isatty(1) != 1 } {
        bail!("--shell requires stdin and stdout to be a terminal");
    }
    let work = std::env::temp_dir().join(format!("virtkit-launch-{}", std::process::id()));
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    let result = build_and_boot(args, &work).await;
    let _ = std::fs::remove_dir_all(&work);
    result
}

async fn build_and_boot(args: &RunArgs, work: &Path) -> Result<()> {
    // 1. fetch the rootfs (docker export or registry pull) as a tar
    let source = if args.oci {
        let ca_pem = match &args.ca {
            Some(p) => Some(std::fs::read(p).with_context(|| format!("reading {}", p.display()))?),
            None => None,
        };
        Source::Oci {
            reference: args.image.clone(),
            username: args.username.clone(),
            password: args.password.clone(),
            ca_pem,
            insecure: args.insecure,
        }
    } else {
        Source::Docker {
            docker: "docker".into(),
            image: args.image.clone(),
        }
    };
    let rootfs_tar = work.join("rootfs.tar");
    source.to_tar(&rootfs_tar).await?;

    // 2. assemble the boot medium (virtkit-agent injected as PID 1)
    let (boot_args, cmdline) = if args.disk {
        println!("virtkit: building ext4 rootfs");
        let rootfs = work.join("root.ext4");
        crate::ext4::build_from_tar(&rootfs_tar, &args.agent, &rootfs)?;
        // throwaway rw qcow2 overlay over the ro raw ext4 (rw raw errors on tmpfs)
        let overlay = work.join("overlay.qcow2");
        let st = Command::new("qemu-img")
            .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
            .arg(&rootfs)
            .arg(&overlay)
            .status()
            .context("running qemu-img")?;
        if !st.success() {
            bail!("qemu-img create failed ({st})");
        }
        (
            vec![
                "--disk".into(),
                format!(
                    "path={},readonly=off,backing_files=on,image_type=qcow2",
                    overlay.display()
                )
                .into(),
            ],
            // no initrd: the kernel mounts /dev/vda (ext4) directly
            format!(
                "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/virtkit-agent \
                 VIRTKIT_HOSTNAME=vm VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
            ),
        )
    } else {
        println!("virtkit: building cpio initramfs");
        let cpio = work.join("initramfs.cpio");
        crate::initramfs::build_initramfs(&rootfs_tar, &args.agent, &cpio)?;
        (
            vec!["--initramfs".into(), cpio.into_os_string()],
            format!(
                "console=ttyS0 rdinit=/usr/local/bin/virtkit-agent VIRTKIT_HOSTNAME=vm \
                 VIRTKIT_VSOCK_PORT={VSOCK_PORT}"
            ),
        )
    };

    // 3. boot
    let vsock = work.join("vsock.sock");
    let console = work.join("console.log");
    println!(
        "virtkit: booting cloud-hypervisor (cpus={}, mem={})",
        args.cpus, args.mem
    );
    let mut ch = spawn_ch(
        &args.cloud_hypervisor,
        &boot_args,
        &cmdline,
        &args.kernel,
        &vsock,
        &console,
        args.cpus,
        &args.mem,
    )?;

    let addr = SocketAddr::VsockMux {
        path: vsock,
        port: VSOCK_PORT,
    };
    let result = drive(&mut ch, &addr, &console, args).await;
    let _ = ch.kill();
    let _ = ch.wait();
    result
}

/// Wait for the in-guest virtkit-agent, run the command, relay its output.
async fn drive(ch: &mut Child, addr: &SocketAddr, console: &Path, args: &RunArgs) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.boot_timeout_secs);
    loop {
        if let Some(status) = ch.try_wait()? {
            bail!(
                "cloud-hypervisor exited during boot ({status})\n{}",
                tail(console, 20)
            );
        }
        if virtkit_agent::status::get_status(addr).await.is_ok() {
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
    if args.shell {
        return run_shell(addr).await;
    }
    let command = if args.command.is_empty() {
        vec![
            "sh".into(),
            "-c".into(),
            "echo PID1=$(cat /proc/1/comm); id; uname -a; cat /etc/os-release | head -1".into(),
        ]
    } else {
        vec!["sh".into(), "-c".into(), args.command.join(" ")]
    };
    let result = crate::executor::exec_script(addr, &command, Vec::new(), None)
        .await
        .context("running the command in the guest")?;
    match result.code {
        Some(0) | None => Ok(()),
        Some(c) => bail!("guest command exited {c}"),
    }
}

/// Attach an interactive shell to the guest: a remote PTY wired to the local
/// terminal (raw mode), sized to it. Returns when the shell exits, whatever its
/// status — a shell that quits non-zero is not a launch failure.
async fn run_shell(addr: &SocketAddr) -> Result<()> {
    use virtkit_agent::messages::{CmdExec, RunMode, Tty};
    let (rows, cols) = virtkit_agent::pty::get_winsize(0).unwrap_or((24, 80));
    let (stream, sink) = virtkit_agent::net::connect(addr)
        .await
        .context("connecting to the VM's virtkit-agent")?;
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
    virtkit_agent::exec::client::client_run_tty(stream, sink, exec)
        .await
        .context("interactive guest shell")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_ch(
    cloud_hypervisor: &Path,
    boot_args: &[std::ffi::OsString],
    cmdline: &str,
    kernel: &Path,
    vsock: &Path,
    console: &Path,
    cpus: u32,
    mem: &str,
) -> Result<Child> {
    let log = std::fs::File::create(console.with_extension("ch.log"))?;
    Command::new(cloud_hypervisor)
        .arg("--kernel")
        .arg(kernel)
        .args(boot_args)
        .arg("--vsock")
        .arg(format!("cid=3,socket={}", vsock.display()))
        .arg("--cpus")
        .arg(format!("boot={cpus}"))
        .arg("--memory")
        .arg(format!("size={mem}"))
        .arg("--serial")
        .arg(format!("file={}", console.display()))
        .arg("--console")
        .arg("off")
        .arg("--cmdline")
        .arg(cmdline)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("spawning {}", cloud_hypervisor.display()))
}

fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

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

/// Spawn a `virtkit switch` giving one VM a userspace LAN + egress over `vsock` (DHCP +
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
    let mut child = Command::new(&exe)
        .arg("switch")
        .arg("--listen")
        .arg(&listen)
        .arg("--gateway")
        .arg(gw.to_string())
        .arg("--prefix")
        .arg(prefix.to_string())
        .stdin(Stdio::null())
        .stdout(swlog.try_clone()?)
        .stderr(swlog)
        .spawn()
        .with_context(|| format!("spawning {} switch", exe.display()))?;
    let dl = Instant::now() + Duration::from_secs(5);
    while !listen.exists() {
        if Instant::now() >= dl {
            let _ = child.kill();
            let _ = child.wait();
            bail!("virtkit switch did not bind {}", listen.display());
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
/// agent. With `net`, a `virtkit switch` gives egress (DHCP + DNS + transparent proxy).
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
    let mut boot_args: Vec<std::ffi::OsString> = vec![
        "--initramfs".into(),
        cpio.into_os_string(),
        "--disk".into(),
        format!(
            "path={},readonly=off,backing_files=on,image_type=qcow2",
            image.display()
        )
        .into(),
    ];
    // Source stages for COPY --from / RUN --mount=from, attached read-only as the next
    // virtio-blk disks (vdb, vdc, … in order) for the guest to mount and read. A forked
    // source is a qcow2 over its parent, so it must be attached as qcow2 with its backing
    // chain enabled; a base source is a plain raw ext4.
    for src in sources {
        boot_args.push("--disk".into());
        let mut a = std::ffi::OsString::from("path=");
        a.push(src);
        if disk_format(src) == "qcow2" {
            a.push(",readonly=on,image_type=qcow2,backing_files=on");
        } else {
            a.push(",readonly=on");
        }
        boot_args.push(a);
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
    let mut virtiofsd: Option<Child> = None;
    if let Some(ctx) = context {
        let sock = work.join("context.fs.sock");
        virtiofsd = Some(crate::fleet::spawn_virtiofsd(&sock, ctx, true, &[], &[])?);
        boot_args.push("--fs".into());
        boot_args.push(format!("tag=context,socket={}", sock.display()).into());
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS=context:{CONTEXT_MOUNT}"));
    }

    let mut switch: Option<Child> = None;
    if net {
        let (child, frag) = spawn_vm_switch(&vsock, &work, NET_VSOCK_PORT).await?;
        switch = Some(child);
        cmdline.push_str(&frag);
    }

    // virtio-fs (the context share) requires shared guest memory.
    let mem = if context.is_some() {
        format!("{mem},shared=on")
    } else {
        mem.to_string()
    };
    let mut ch = spawn_ch(
        cloud_hypervisor,
        &boot_args,
        &cmdline,
        kernel,
        &vsock,
        &console,
        cpus,
        &mem,
    )?;
    let addr = SocketAddr::VsockMux {
        path: vsock,
        port: VSOCK_PORT,
    };
    let deadline = Instant::now() + Duration::from_secs(boot_timeout_secs);
    loop {
        if let Some(status) = ch.try_wait()? {
            bail!(
                "cloud-hypervisor exited during boot ({status})\n{}",
                tail(&console, 20)
            );
        }
        if virtkit_agent::status::get_status(&addr).await.is_ok() {
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
