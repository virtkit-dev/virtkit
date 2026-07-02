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

use std::path::PathBuf;
use std::process::Command;

/// A virtio-blk disk, attached in order (first = `/dev/vda`, then `vdb`, …).
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

/// A virtio-fs share: the tag the guest mounts by and the virtiofsd socket.
pub struct FsShare {
    pub tag: String,
    pub socket: PathBuf,
}

/// Guest networking. `switch`-mode guests add no device here — the in-guest agent
/// bridges eth0 to the userspace switch over vsock — so they use [`Net::None`].
pub enum Net {
    None,
    Tap { tap: String, mac: String },
}

/// Everything needed to boot one microVM, independent of the VMM.
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

/// A virtual machine monitor that can boot a [`VmSpec`].
pub trait Vmm {
    /// Build the un-spawned [`Command`] that boots `spec`. Only arguments are set;
    /// the caller owns stdio and spawn/lifecycle semantics.
    fn command(&self, spec: &VmSpec) -> Command;
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
            }],
            vsock_cid: 3,
            vsock_socket: "/job/vsock.sock".into(),
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
