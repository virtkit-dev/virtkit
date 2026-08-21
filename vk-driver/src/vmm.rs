//! VMM abstraction. A [`Vmm`] turns a [`VmSpec`] — everything needed to boot one
//! microVM, expressed independently of the hypervisor — into a configured
//! [`Command`]. cloud-hypervisor is the sole implementation today.
//!
//! The command is returned un-spawned: each caller owns its own lifecycle (the CI
//! path spawns it detached with a pidfile and shuts it down over the CH API
//! socket; the dev `run`/build paths hold the `Child` and kill it). Running
//! every VMM as a subprocess keeps the per-VM crash/seccomp boundary and lets an
//! in-process VMM (e.g. libkrun) plug in later as a self-subcommand without
//! touching callers.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use vk_core::addr::SocketAddr;

/// Env var carrying the JSON `VmSpec` to a libkrun boot child. It rides the environment
/// (not argv) so `ps aux` shows just the VM's process name; its presence also selects the
/// boot-child path in `main` (no positional subcommand needed).
pub const BOOT_SPEC_ENV: &str = "VIRTKIT_BOOT_SPEC";

/// Env var carrying the VM process name to the libkrun boot child; the vendored libkrun
/// reads it for the 15-char `comm` (see `krun_start_enter` in third_party/libkrun).
pub const VM_NAME_ENV: &str = "VIRTKIT_VM_NAME";

/// Default `--vm-name` template. `{name}` expands to the per-VM unit name (a Dockerfile
/// stage, an image, or a compose service).
pub const DEFAULT_VM_NAME_TEMPLATE: &str = "vk:{name}";

/// The `--vm-name` template, set once per process from the CLI. Booting happens across
/// several call sites (run, compose siblings, stage builds) that all share this process,
/// so a process-global spares threading the template through every signature. Separate
/// processes (the boot child, a CI job) leave it unset and fall back to the default.
static VM_NAME_TEMPLATE: OnceLock<String> = OnceLock::new();

/// Record the `--vm-name` template for this process. First call wins; later calls (e.g. a
/// test) are ignored.
pub fn set_vm_name_template(template: String) {
    let _ = VM_NAME_TEMPLATE.set(template);
}

/// Resolve a VM process name for `unit` (the stage/image/service name) by expanding `{name}`
/// in the active template (default [`DEFAULT_VM_NAME_TEMPLATE`]).
pub fn resolve_proc_name(unit: &str) -> String {
    let template = VM_NAME_TEMPLATE
        .get()
        .map(String::as_str)
        .unwrap_or(DEFAULT_VM_NAME_TEMPLATE);
    expand_vm_name(template, unit)
}

/// Substitute `{name}` in a `--vm-name` template with the unit name.
fn expand_vm_name(template: &str, unit: &str) -> String {
    template.replace("{name}", unit)
}

/// Serde fallback for [`VmSpec::proc_name`] when a spec predates the field.
fn default_proc_name() -> String {
    resolve_proc_name("vm")
}

/// A virtio-blk disk image format. Drives `image_type=` and whether a backing chain is
/// resolved.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DiskFormat {
    /// A raw base ext4 (or another plain block image).
    Raw,
    /// A CoW overlay or a forked build stage.
    Qcow2,
    /// A `.vk_ro_img` manifest: a read-only, on-demand-decompressing view over a cached
    /// build-stage image's chunks (libkrun only — see `third_party/libkrun`'s
    /// `lazy_chunk_storage`). Never valid under cloud-hypervisor.
    VkLazyChunks,
}

/// A virtio-blk disk, attached in order (first = `/dev/vda`, then `vdb`, …).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Disk {
    pub path: PathBuf,
    pub format: DiskFormat,
    pub readonly: bool,
    /// If set (libkrun build stages only), the VMM serves a dirty-drain control protocol
    /// on this Unix socket so a checkpoint captures only the delta. `None` = untracked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty_control_socket: Option<PathBuf>,
}

impl Disk {
    /// A rw CoW overlay (qcow2 over a backing base) — the common boot disk.
    pub fn overlay(path: PathBuf) -> Self {
        Disk {
            path,
            format: DiskFormat::Qcow2,
            readonly: false,
            dirty_control_socket: None,
        }
    }

    /// A raw disk attached as-is (no qcow2, no backing chain) — a plain block device
    /// handed to the guest after the rootfs (vdb, vdc, …). Used by `vk run --disk`
    /// to expose a host file the guest writes directly, e.g. a disk image being
    /// partitioned and installed into.
    pub fn raw(path: PathBuf, readonly: bool) -> Self {
        Disk {
            path,
            format: DiskFormat::Raw,
            readonly,
            dirty_control_socket: None,
        }
    }

    /// Enable dirty-block tracking, serving the drain protocol on `socket` (libkrun only).
    pub fn with_dirty_control(mut self, socket: PathBuf) -> Self {
        self.dirty_control_socket = Some(socket);
        self
    }

    /// cloud-hypervisor `--disk` value. qcow2 disks resolve their backing chain
    /// (overlays/forked stages); a raw disk omits both keys (CH defaults to raw).
    /// `VkLazyChunks` never reaches here — it is only ever attached under libkrun.
    fn ch_value(&self) -> String {
        let mut v = format!(
            "path={},readonly={}",
            self.path.display(),
            if self.readonly { "on" } else { "off" }
        );
        if self.format == DiskFormat::Qcow2 {
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
    /// virtiofsd-style UID id-map spec strings (`type:from:to[:count]`) applied at the
    /// guest↔host boundary; empty = identity. Under cloud-hypervisor these become
    /// `--uid-map` args to the bundled virtiofsd; under libkrun they go to
    /// `krun_add_virtiofs4`. `gid_map` is the same for GIDs.
    #[serde(default)]
    pub uid_map: Vec<String>,
    #[serde(default)]
    pub gid_map: Vec<String>,
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
    /// Exec-style channel (host→guest): libkrun listens on `<base>_<port>` and
    /// forwards host connections to guest `port` — the raw, relay-free path a
    /// `vsock-auto://<base>:<port>` client prefers. Cloud-hypervisor ignores the
    /// entry (its hybrid socket at `base` serves every port behind the CONNECT
    /// handshake, which is the same client's fallback).
    pub fn exec(base: &Path, port: u32) -> Self {
        VsockPort {
            port,
            socket: hybrid_socket(base, port),
            listen: true,
        }
    }

    /// Guest→host bridge (switch, ssh-agent): the guest dials `port` and the VMM
    /// forwards to the host listener at `<base>_<port>` — the same `_<port>` suffix
    /// the hybrid-vsock host sockets already use.
    pub fn bridge(base: &Path, port: u32) -> Self {
        VsockPort {
            port,
            socket: hybrid_socket(base, port),
            listen: false,
        }
    }
}

/// The host-side socket for guest `port` on the hybrid-vsock convention:
/// `<base>_<port>`. Re-exported from vk-core, where `vsock-auto://` resolution
/// shares the single spelling of that suffix.
pub use vk_core::net::hybrid_socket;

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
    /// virtio-balloon with free-page reporting: the guest hands pages it frees back to
    /// the host mid-run, so concurrent VMs can overcommit safely. Honored by both
    /// backends — cloud-hypervisor gates its `--balloon` argument on it, and the libkrun
    /// backend, which attaches a balloon by default, opts out through the vendored
    /// `krun_disable_balloon`. Costs one virtio-pci slot on libkrun.
    pub balloon: bool,
    /// Serial console log file (`--serial file=…`).
    pub serial_log: PathBuf,
    /// Keep `console=ttyS0` instead of rewriting it to `console=hvc0` (libkrun): needed
    /// for a BYO stock kernel whose virtio-console (hvc0) is modular, so early boot output
    /// only reaches the legacy serial. Set by `vk run --console-serial`. An image kernel
    /// keeps serial regardless (via the `VIRTKIT_KERNEL=image` cmdline token).
    #[serde(default)]
    pub console_serial: bool,
    /// Expose the guest PMU (`vk run --pmu`): the libkrun backend leaves CPUID
    /// leaf 0xA as KVM reports it (vendored `krun_set_pmu` patch), so in-guest
    /// perf gets hardware counters via KVM's vPMU. Default off — host counters
    /// are a side-channel surface, for trusted dev VMs only. cloud-hypervisor
    /// has no equivalent; that backend warns and boots without.
    #[serde(default)]
    pub pmu: bool,
    /// Expose VMX/SVM to the guest (`vk run --nested`) so it can run KVM guests of
    /// its own — `vk` inside `vk`. The libkrun backend keeps the host's CPUID bit
    /// (`krun_set_nested_virt`), which it otherwise masks; cloud-hypervisor has no
    /// such knob and passes the host's bit through whatever this says, so its guests
    /// nest whenever the host allows it. Default off: nesting widens the guest's
    /// attack surface on host KVM, and the host must allow it
    /// ([`host_nesting_enabled`]).
    #[serde(default)]
    pub nested: bool,
    /// CH API socket for graceful shutdown (the detached CI VM). `None` = no API
    /// socket (the held-`Child` paths kill the process directly).
    pub api_socket: Option<PathBuf>,
    /// Fds backing unlinked boot media (`scratch::ScratchFile`), whose
    /// `/proc/self/fd/<n>` paths appear in `kernel`/`initramfs`/`disks` — or in a
    /// qcow2 backing reference. `run::spawn_vmm` clears CLOEXEC on each for the VMM
    /// spawn, so the child inherits them (same numbers) and the paths resolve there.
    #[serde(default)]
    pub pass_fds: Vec<i32>,
    /// Process name for the VMM subprocess: sets `comm` (top/htop, 15-char capped) and
    /// argv[0] (`ps aux`). Derived from `--vm-name` (default `vk:{name}`) via
    /// [`resolve_proc_name`]. Only the libkrun backend applies it — cloud-hypervisor keeps
    /// its own binary name.
    #[serde(default = "default_proc_name")]
    pub proc_name: String,
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
        // No CH equivalent of libkrun's krun_set_pmu (x86 CH exposes no vPMU knob):
        // boot without rather than fail, but say so — otherwise the user only sees
        // `<not supported>` from perf inside the guest.
        if spec.pmu {
            eprintln!(
                "virtkit: warning: --pmu is not supported by the cloud-hypervisor backend; \
                 booting without a guest PMU"
            );
        }
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

/// libkrun: boots `spec` by re-execing this binary as a per-VM subprocess that links
/// libkrun and drives its C API (see [`crate::libkrun_sys`]). Running it as a subprocess
/// keeps the same lifecycle as [`CloudHypervisor`] (held `Child` / `spawn_tied`), with no
/// in-process VMM in the orchestrator.
#[cfg(feature = "libkrun")]
pub struct Libkrun;

#[cfg(feature = "libkrun")]
impl Vmm for Libkrun {
    fn command(&self, spec: &VmSpec) -> Command {
        use std::os::unix::process::CommandExt;

        let json = serde_json::to_string(spec).expect("serializing VmSpec to JSON");
        // self_exe() is always the running binary — never a different `vk` resolved
        // from $PATH — and survives the on-disk binary being replaced mid-run.
        let mut cmd = Command::new(crate::spawn::self_exe());
        // Present as the VM's process name (e.g. `vk:myapp`) rather than
        // `vk __libkrun-boot <json>`: argv[0] carries the name (`ps aux`), the spec rides
        // BOOT_SPEC_ENV off argv (so `ps` stays clean), and VM_NAME_ENV feeds libkrun's
        // 15-char `comm`. `main` dispatches on BOOT_SPEC_ENV's presence.
        cmd.arg0(&spec.proc_name)
            .env(BOOT_SPEC_ENV, json)
            .env(VM_NAME_ENV, &spec.proc_name);
        cmd
    }

    fn name(&self) -> &'static str {
        "libkrun"
    }
}

/// The `[vmm]` config choice, set once in `cli_main` from the loaded config. `None` (not
/// yet set, or the key was absent) leaves the backend to the env var / libkrun default.
static CONFIG_BACKEND: std::sync::OnceLock<Option<crate::config::VmmBackend>> =
    std::sync::OnceLock::new();

/// Record the config's `vmm` key so [`libkrun_selected`] can consult it. Called once after
/// the config loads, before any boot. The `VIRTKIT_VMM` env var still takes precedence.
pub fn set_config_backend(backend: Option<crate::config::VmmBackend>) {
    let _ = CONFIG_BACKEND.set(backend);
}

/// Whether the libkrun backend is selected. libkrun is the default when it is compiled
/// in (the `libkrun` feature). The precedence is `VIRTKIT_VMM` (read on each call so every
/// CI phase — prepare/run/cleanup, separate processes sharing gitlab-runner's environment —
/// agrees), then the config `vmm` key, then libkrun. Set `cloud-hypervisor` to opt out —
/// e.g. for Windows guests, which libkrun cannot boot.
pub fn libkrun_selected() -> bool {
    if !cfg!(feature = "libkrun") {
        return false;
    }
    match std::env::var("VIRTKIT_VMM").ok().as_deref() {
        Some("cloud-hypervisor") | Some("cloud_hypervisor") | Some("ch") => return false,
        Some("libkrun") => return true,
        _ => {}
    }
    !matches!(
        CONFIG_BACKEND.get().copied().flatten(),
        Some(crate::config::VmmBackend::CloudHypervisor)
    )
}

/// Whether the host lets a guest run guests of its own — `kvm_intel`/`kvm_amd`'s
/// `nested` module parameter. Backend-agnostic on purpose: libkrun's own
/// `krun_check_nested_virt` reads these same two files (and is compiled out of a
/// cloud-hypervisor-only build), while cloud-hypervisor has no nesting knob at all —
/// it passes the host's VMX/SVM CPUID bit through — so this is what decides nesting
/// on either backend.
pub fn host_nesting_enabled() -> bool {
    nesting_enabled_in(Path::new("/sys/module"))
}

/// [`host_nesting_enabled`] against an arbitrary `/sys/module` root, so the parse is
/// testable. Absent files mean no nesting: a module that is not loaded (or a host
/// that is not x86) exposes no parameter to read.
fn nesting_enabled_in(sys_module: &Path) -> bool {
    ["kvm_intel", "kvm_amd"].iter().any(|module| {
        std::fs::read_to_string(sys_module.join(module).join("parameters/nested"))
            .is_ok_and(|enabled| matches!(enabled.trim(), "1" | "Y" | "y"))
    })
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

/// The exec-channel connect address: `vsock-auto://<base>:<port>` on every
/// backend. The client resolves the best path at connect time — libkrun's
/// dedicated per-port listener (raw, no relay) when it answers, else the CONNECT
/// handshake on Cloud Hypervisor's hybrid base socket. One address form, no
/// backend knowledge anywhere.
pub fn exec_addr(vsock_socket: &Path, port: u32) -> SocketAddr {
    SocketAddr::VsockAuto {
        path: vsock_socket.to_path_buf(),
        port,
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

    #[test]
    fn host_nesting_reads_either_module_parameter() {
        let root = std::env::temp_dir().join(format!("vk-nested-{}", std::process::id()));
        // A panicking earlier run leaks its tree, and a reused pid would then start from
        // an enabled parameter — the first assertion below is exactly what that breaks.
        let _ = std::fs::remove_dir_all(&root);
        let write = |module: &str, value: &str| {
            let dir = root.join(module).join("parameters");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("nested"), value).unwrap();
        };
        // neither module present: nothing to read, so no nesting
        std::fs::create_dir_all(&root).unwrap();
        assert!(!nesting_enabled_in(&root));
        // "1" or "Y" (kvm_amd vs kvm_intel), matched case-insensitively as libkrun does,
        // with the newline sysfs writes
        for enabled in ["1", "Y\n", "y"] {
            write("kvm_intel", enabled);
            assert!(
                nesting_enabled_in(&root),
                "{enabled:?} should read as nested"
            );
        }
        write("kvm_intel", "0\n");
        assert!(!nesting_enabled_in(&root));
        // either vendor's module is enough — only one matches the host CPU
        write("kvm_amd", "1\n");
        assert!(nesting_enabled_in(&root));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn vm_name_template_expands_name() {
        assert_eq!(
            expand_vm_name(DEFAULT_VM_NAME_TEMPLATE, "builder"),
            "vk:builder"
        );
        assert_eq!(expand_vm_name("alpine {name} run", "web"), "alpine web run");
        // no placeholder → the template is the literal name
        assert_eq!(expand_vm_name("my-vm", "web"), "my-vm");
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
                uid_map: Vec::new(),
                gid_map: Vec::new(),
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
            console_serial: false,
            pmu: false,
            nested: false,
            api_socket: Some("/job/api.sock".into()),
            pass_fds: Vec::new(),
            proc_name: "vk:ci".into(),
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

    /// A minimal guest: agent initramfs + a rw qcow2 stage disk + a read-only raw
    /// source disk (COPY --from style), with API/net/balloon off and unshared memory —
    /// the balloon-off spelling `[vm] balloon = false` selects, gating `--balloon` away.
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
                    format: DiskFormat::Raw,
                    readonly: true,
                    dirty_control_socket: None,
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
            console_serial: false,
            pmu: false,
            nested: false,
            api_socket: None,
            pass_fds: Vec::new(),
            proc_name: "vk:build".into(),
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
