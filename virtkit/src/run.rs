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
