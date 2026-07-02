//! VMM abstraction. A [`Vmm`] turns a [`VmSpec`] — everything needed to boot one
//! microVM, expressed independently of the hypervisor — into a configured
//! [`Command`]. cloud-hypervisor is the sole implementation today.
//!
//! The command is returned un-spawned: each caller owns its own lifecycle (the CI
//! path spawns it detached with a pidfile and shuts it down over the CH API
//! socket; the dev `run`/`fleet`/build paths hold the `Child` and kill it). Running
//! every VMM as a subprocess keeps the per-VM crash/seccomp boundary and lets an
//! in-process VMM (e.g. libkrun) plug in later as a self-subcommand without
//! touching callers.

use std::path::{Path, PathBuf};
use std::process::Command;

use vk_core::addr::SocketAddr;

/// A virtio-blk disk, attached in order (first = `/dev/vda`, then `vdb`, …).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Disk {
    pub path: PathBuf,
    /// `true` for a qcow2 (a CoW overlay or a forked build stage); `false` for a
    /// raw base ext4. Drives `image_type=` and whether a backing chain is resolved.
    pub qcow2: bool,
    pub readonly: bool,
}

impl Disk {
    /// A rw CoW overlay (qcow2 over a backing base) — the common boot disk.
    pub fn overlay(path: PathBuf) -> Self {
        Disk {
            path,
            qcow2: true,
            readonly: false,
        }
    }

    /// cloud-hypervisor `--disk` value. qcow2 disks resolve their backing chain
    /// (overlays/forked stages); a raw disk omits both keys (CH defaults to raw).
    fn ch_value(&self) -> String {
        let mut v = format!(
            "path={},readonly={}",
            self.path.display(),
            if self.readonly { "on" } else { "off" }
        );
        if self.qcow2 {
            v.push_str(",image_type=qcow2,backing_files=on");
        }
        v
    }
}

/// A virtio-fs share: the tag the guest mounts by, plus the two ways a backend
/// serves it. cloud-hypervisor connects to an external virtiofsd on `socket`; libkrun
/// has no external vhost-user-fs, so it mounts `host_dir` directly with its built-in
/// virtio-fs (and no separate virtiofsd is spawned — see the boot sites).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FsShare {
    pub tag: String,
    pub socket: PathBuf,
    pub host_dir: PathBuf,
    pub read_only: bool,
}

/// Guest networking. `switch`-mode guests add no device here — the in-guest agent
/// bridges eth0 to the userspace switch over vsock — so they use [`Net::None`].
#[derive(serde::Serialize, serde::Deserialize)]
pub enum Net {
    None,
    Tap { tap: String, mac: String },
}

/// A guest vsock port mapped to a host-side unix socket. This is how the libkrun
/// backend is told about vsock channels; cloud-hypervisor derives the same wiring
/// from its hybrid `--vsock` socket plus the `_<port>` suffix convention and ignores
/// this list.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VsockPort {
    pub port: u32,
    pub socket: PathBuf,
    /// `true`: the VMM listens on `socket` and forwards host connections to the guest
    /// `port` (host→guest, e.g. the exec channel). `false`: the guest dials `port` and
    /// the VMM forwards to `socket`, where the host already listens (guest→host, e.g.
    /// the switch and ssh-agent bridges).
    pub listen: bool,
}

impl VsockPort {
    /// Exec-style channel: the VMM listens on `base` and forwards host connections to
    /// guest `port`. Mirrors cloud-hypervisor's hybrid base socket (host→guest).
    pub fn exec(base: &Path, port: u32) -> Self {
        VsockPort {
            port,
            socket: base.to_path_buf(),
            listen: true,
        }
    }

    /// Guest→host bridge (switch, ssh-agent): the guest dials `port` and the VMM
    /// forwards to the host listener at `<base>_<port>` — the same `_<port>` suffix
    /// the hybrid-vsock host sockets already use.
    pub fn bridge(base: &Path, port: u32) -> Self {
        let mut socket = base.as_os_str().to_owned();
        socket.push(format!("_{port}"));
        VsockPort {
            port,
            socket: socket.into(),
            listen: false,
        }
    }
}

/// Everything needed to boot one microVM, independent of the VMM.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VmSpec {
    pub kernel: PathBuf,
    pub cmdline: String,
    /// virtio-blk disks in attach order (empty for a pure-initramfs guest).
    pub disks: Vec<Disk>,
    /// initramfs/initrd: the agent initramfs (a pivot boot) or a self-booting
    /// image's own initrd. `None` when the kernel mounts a disk root directly.
    pub initramfs: Option<PathBuf>,
    pub shares: Vec<FsShare>,
    pub vsock_cid: u32,
    pub vsock_socket: PathBuf,
    /// Per-port vsock map for the libkrun backend (see [`VsockPort`]);
    /// cloud-hypervisor ignores it and uses `vsock_socket` + the `_<port>` convention.
    pub vsock_ports: Vec<VsockPort>,
    pub cpus: u32,
    /// Memory size token, e.g. `"8G"`. [`Self::shared_mem`] appends `,shared=on`,
    /// which virtio-fs requires (and is harmless without).
    pub mem: String,
    pub shared_mem: bool,
    pub net: Net,
    pub balloon: bool,
    /// Serial console log file (`--serial file=…`).
    pub serial_log: PathBuf,
    /// CH API socket for graceful shutdown (the detached CI VM). `None` = no API
    /// socket (the held-`Child` paths kill the process directly).
    pub api_socket: Option<PathBuf>,
}

/// A virtual machine monitor that can boot a [`VmSpec`]. `Send` so a boxed `dyn Vmm`
/// can be held across the async boot-wait loop (the multi-threaded runtime).
pub trait Vmm: Send {
    /// Build the un-spawned [`Command`] that boots `spec`. Only arguments are set;
    /// the caller owns stdio and spawn/lifecycle semantics.
    fn command(&self, spec: &VmSpec) -> Command;

    /// Backend name, for user-facing log lines.
    fn name(&self) -> &'static str;
}

/// cloud-hypervisor: boots `spec` as an external `cloud-hypervisor` process.
pub struct CloudHypervisor {
    pub bin: PathBuf,
}

impl Vmm for CloudHypervisor {
    fn command(&self, spec: &VmSpec) -> Command {
        let mut cmd = Command::new(&self.bin);
        if let Some(api) = &spec.api_socket {
            cmd.arg("--api-socket").arg(api);
        }
        cmd.arg("--kernel").arg(&spec.kernel);
        for disk in &spec.disks {
            cmd.arg("--disk").arg(disk.ch_value());
        }
        if let Some(initramfs) = &spec.initramfs {
            cmd.arg("--initramfs").arg(initramfs);
        }
        for share in &spec.shares {
            cmd.arg("--fs").arg(format!(
                "tag={},socket={}",
                share.tag,
                share.socket.display()
            ));
        }
        let mem = if spec.shared_mem {
            format!("size={},shared=on", spec.mem)
        } else {
            format!("size={}", spec.mem)
        };
        cmd.arg("--vsock")
            .arg(format!(
                "cid={},socket={}",
                spec.vsock_cid,
                spec.vsock_socket.display()
            ))
            .arg("--cpus")
            .arg(format!("boot={}", spec.cpus))
            .arg("--memory")
            .arg(mem)
            .arg("--serial")
            .arg(format!("file={}", spec.serial_log.display()))
            .arg("--console")
            .arg("off")
            .arg("--cmdline")
            .arg(&spec.cmdline);
        if let Net::Tap { tap, mac } = &spec.net {
            cmd.arg("--net").arg(format!("tap={tap},mac={mac}"));
        }
        if spec.balloon {
            // size=0: no static balloon, just give freed guest pages back to the
            // host so concurrent jobs overcommit safely (guest CONFIG_PAGE_REPORTING).
            cmd.arg("--balloon")
                .arg("size=0,deflate_on_oom=on,free_page_reporting=on");
        }
        cmd
    }

    fn name(&self) -> &'static str {
        "cloud-hypervisor"
    }
}

/// libkrun: boots `spec` by re-execing `vk __libkrun-boot <spec-json>` — a per-VM
/// subprocess that links libkrun and drives its C API (see [`crate::libkrun_sys`]).
/// Running it as a subprocess keeps the same lifecycle as [`CloudHypervisor`]
/// (held `Child` / `spawn_tied`), with no in-process VMM in the orchestrator.
#[cfg(feature = "libkrun")]
pub struct Libkrun;

#[cfg(feature = "libkrun")]
impl Vmm for Libkrun {
    fn command(&self, spec: &VmSpec) -> Command {
        let json = serde_json::to_string(spec).expect("serializing VmSpec to JSON");
        // /proc/self/exe is always the running binary — never a different `vk`
        // resolved from $PATH — should current_exe() ever fail.
        let exe = std::env::current_exe().unwrap_or_else(|_| "/proc/self/exe".into());
        let mut cmd = Command::new(exe);
        cmd.arg("__libkrun-boot").arg(json);
        cmd
    }

    fn name(&self) -> &'static str {
        "libkrun"
    }
}

/// Whether the libkrun backend is selected. libkrun is the default when it is compiled
/// in (the `libkrun` feature); set `VIRTKIT_VMM=cloud-hypervisor` to opt out — e.g. for
/// Windows guests, which libkrun cannot boot. Read on each call so every CI phase
/// (prepare/run/cleanup run as separate processes) agrees — gitlab-runner passes the
/// same environment to each exec.
pub fn libkrun_selected() -> bool {
    if !cfg!(feature = "libkrun") {
        return false;
    }
    !matches!(
        std::env::var("VIRTKIT_VMM").ok().as_deref(),
        Some("cloud-hypervisor") | Some("cloud_hypervisor") | Some("ch")
    )
}

/// The selected VMM backend for a boot.
pub fn selected(cloud_hypervisor: &Path) -> Box<dyn Vmm> {
    #[cfg(feature = "libkrun")]
    if libkrun_selected() {
        return Box::new(Libkrun);
    }
    Box::new(CloudHypervisor {
        bin: cloud_hypervisor.to_path_buf(),
    })
}

/// The exec-channel connect address for the selected backend: libkrun listens on the
/// base socket and forwards raw to the guest (a plain unix connect), while
/// cloud-hypervisor multiplexes guest ports behind the hybrid-vsock `CONNECT`
/// handshake.
pub fn exec_addr(vsock_socket: &Path, port: u32) -> SocketAddr {
    if libkrun_selected() {
        SocketAddr::Unix(vsock_socket.to_path_buf())
    } else {
        SocketAddr::VsockMux {
            path: vsock_socket.to_path_buf(),
            port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// The CI path: API socket (graceful shutdown), a rw qcow2 overlay root,
    /// a virtio-fs share, a leased tap, balloon, shared memory.
    #[test]
    fn ci_disk_with_tap_balloon_api() {
        let ch = CloudHypervisor {
            bin: "cloud-hypervisor".into(),
        };
        let spec = VmSpec {
            kernel: "/k/vmlinux".into(),
            cmdline: "console=ttyS0 root=/dev/vda".into(),
            disks: vec![Disk::overlay("/job/overlay.qcow2".into())],
            initramfs: None,
            shares: vec![FsShare {
                tag: "workdir".into(),
                socket: "/job/vfsd.sock".into(),
                host_dir: "/host/workdir".into(),
                read_only: false,
            }],
            vsock_cid: 3,
            vsock_socket: "/job/vsock.sock".into(),
            vsock_ports: vec![],
            cpus: 4,
            mem: "8G".into(),
            shared_mem: true,
            net: Net::Tap {
                tap: "civtap0".into(),
                mac: "52:54:00:d2:f0:01".into(),
            },
            balloon: true,
            serial_log: "/job/console.log".into(),
            api_socket: Some("/job/api.sock".into()),
        };
        assert_eq!(
            args(&ch.command(&spec)),
            vec![
                "--api-socket",
                "/job/api.sock",
                "--kernel",
                "/k/vmlinux",
                "--disk",
                "path=/job/overlay.qcow2,readonly=off,image_type=qcow2,backing_files=on",
                "--fs",
                "tag=workdir,socket=/job/vfsd.sock",
                "--vsock",
                "cid=3,socket=/job/vsock.sock",
                "--cpus",
                "boot=4",
                "--memory",
                "size=8G,shared=on",
                "--serial",
                "file=/job/console.log",
                "--console",
                "off",
                "--cmdline",
                "console=ttyS0 root=/dev/vda",
                "--net",
                "tap=civtap0,mac=52:54:00:d2:f0:01",
                "--balloon",
                "size=0,deflate_on_oom=on,free_page_reporting=on",
            ]
        );
    }

    /// A build session: agent initramfs + a rw qcow2 stage disk + a read-only raw
    /// source disk (COPY --from), no API/net/balloon, unshared memory.
    #[test]
    fn build_session_initramfs_and_source_disks() {
        let ch = CloudHypervisor {
            bin: "/usr/bin/cloud-hypervisor".into(),
        };
        let spec = VmSpec {
            kernel: "/k/vmlinux".into(),
            cmdline: "console=ttyS0 rdinit=/init".into(),
            disks: vec![
                Disk::overlay("/w/stage.qcow2".into()),
                Disk {
                    path: "/w/source.ext4".into(),
                    qcow2: false,
                    readonly: true,
                },
            ],
            initramfs: Some("/w/initramfs.cpio".into()),
            shares: vec![],
            vsock_cid: 3,
            vsock_socket: "/w/vsock.sock".into(),
            vsock_ports: vec![],
            cpus: 2,
            mem: "2G".into(),
            shared_mem: false,
            net: Net::None,
            balloon: false,
            serial_log: "/w/console.log".into(),
            api_socket: None,
        };
        assert_eq!(
            args(&ch.command(&spec)),
            vec![
                "--kernel",
                "/k/vmlinux",
                "--disk",
                "path=/w/stage.qcow2,readonly=off,image_type=qcow2,backing_files=on",
                "--disk",
                "path=/w/source.ext4,readonly=on",
                "--initramfs",
                "/w/initramfs.cpio",
                "--vsock",
                "cid=3,socket=/w/vsock.sock",
                "--cpus",
                "boot=2",
                "--memory",
                "size=2G",
                "--serial",
                "file=/w/console.log",
                "--console",
                "off",
                "--cmdline",
                "console=ttyS0 rdinit=/init",
            ]
        );
    }
}
