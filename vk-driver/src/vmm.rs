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
// The deterministic MAC for a switch address (`52:54:00` + the low three octets), the
// identity the switch's per-MAC DHCP reservations and this module's NICs agree on.
use vk_core::net::mac_for_ip;

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

    /// Attach a disk volume according to its header: new qcow2 or legacy raw ext4. Honor
    /// `readonly` and reject `.vk_ro_img` chunk views, which are not disks.
    pub fn for_image(path: PathBuf, readonly: bool) -> anyhow::Result<Self> {
        use anyhow::Context;
        let f = std::fs::File::open(&path)
            .with_context(|| format!("opening disk {}", path.display()))?;
        let format = match crate::qcow2::sniff_kind(&f) {
            crate::qcow2::ImageKind::Qcow2 => DiskFormat::Qcow2,
            crate::qcow2::ImageKind::Raw => DiskFormat::Raw,
            crate::qcow2::ImageKind::Lazy => {
                anyhow::bail!("{}: a chunk view is not a disk", path.display())
            }
        };
        Ok(Disk {
            path,
            format,
            readonly,
            dirty_control_socket: None,
        })
    }

    /// Enable dirty-block tracking, serving the drain protocol on `socket` (libkrun only).
    pub fn with_dirty_control(mut self, socket: PathBuf) -> Self {
        self.dirty_control_socket = Some(socket);
        self
    }

    /// cloud-hypervisor `--disk` value. A qcow2 disk carries `image_type=qcow2,backing_files=on`
    /// so CH resolves any backing chain (a root overlay's forked stages); a disk-volume qcow2
    /// has no chain, and the flag is then a harmless no-op. A raw disk omits both keys (CH
    /// defaults to raw). `VkLazyChunks` never reaches here — it is only attached under libkrun.
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

/// A virtio-fs DAX window maps shared files into guest address space for direct access to
/// the host page cache, avoiding a second copy through FUSE. `off` disables the window.
///
/// Only the libkrun backend has a window; cloud-hypervisor's virtio-fs has no DAX path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dax {
    /// No window: file data is copied into the guest's page cache on every read.
    Off,
    /// A window this many bytes wide, per share.
    Window(u64),
}

/// Default per-share window. Reserves address space, not memory: the host maps and unmaps
/// file ranges on demand, so it costs nothing until used. Sized for a working tree, not RAM.
pub const DAX_DEFAULT: Dax = Dax::Window(8 << 30);

/// Smallest useful window: the guest's FUSE DAX layer hands out 2 MiB ranges.
const DAX_MIN: u64 = 2 << 20;

/// Ceiling on the windows one guest is given in total: the span the guest's DSDT declares
/// as a PCI host-bridge window, which is the only place a window's BAR survives Linux's
/// enumeration. Kept in step with `SHM_MEM_SIZE` in
/// `third_party/libkrun/src/arch/src/x86_64/layout.rs`, which fixes the span; a share past
/// the ceiling boots without a window rather than off the end of it.
pub const DAX_TOTAL_MAX: u64 = 64 << 30;

/// Most guest RAM, in MiB, that still leaves the span reachable. The span starts at a fixed
/// `SHM_MEM_START` (64 GiB, same layout file as [`DAX_TOTAL_MAX`]) and a guest whose RAM
/// reaches into it is given no span at all — its RAM would be where the windows go. The
/// 512 MiB below 64 GiB is the 32-bit MMIO hole libkrun leaves under 4 GiB, which the guest's
/// RAM is pushed above.
pub const DAX_MAX_GUEST_MIB: u64 = 64768;

impl Dax {
    /// The window in bytes, or `None` when off.
    pub fn window(self) -> Option<u64> {
        match self {
            Dax::Off => None,
            Dax::Window(bytes) => Some(bytes),
        }
    }
}

impl std::str::FromStr for Dax {
    type Err = String;

    /// `off`, or a window size: `<n>G`, `<n>M`, or a bare MiB count.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        // The spellings a YAML or TOML scalar turns "no" into; they are not sizes, so `0M`
        // stays an error rather than a fourth way to write it.
        if matches!(s, "off" | "false" | "0" | "no") {
            return Ok(Dax::Off);
        }
        let (digits, scale) = match s.strip_suffix(['G', 'g']) {
            Some(d) => (d, 1 << 30),
            None => (s.strip_suffix(['M', 'm']).unwrap_or(s), 1 << 20),
        };
        digits
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(scale))
            .filter(|bytes| (DAX_MIN..=DAX_TOTAL_MAX).contains(bytes))
            .map(Dax::Window)
            .ok_or_else(|| {
                format!(
                    "expected off, or a window of 2M..{}G written <n>G, <n>M or a MiB count, \
                     got {s:?}",
                    DAX_TOTAL_MAX >> 30
                )
            })
    }
}

impl std::fmt::Display for Dax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dax::Off => f.write_str("off"),
            // Whole gibibytes as `8G`, the spelling the docs and the CLI use; anything
            // else in MiB, which every size this parser takes can be written in.
            Dax::Window(bytes) if bytes.is_multiple_of(1 << 30) => write!(f, "{}G", bytes >> 30),
            Dax::Window(bytes) => write!(f, "{}M", bytes >> 20),
        }
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
    /// Bytes of guest address space for this share's DAX window; `None` = no window.
    /// libkrun passes it to `krun_add_virtiofs4` as its `shm_size`.
    #[serde(default)]
    pub dax: Option<u64>,
    /// virtiofsd-style UID id-map spec strings (`type:from:to[:count]`) applied at the
    /// guest↔host boundary; empty = identity. Under cloud-hypervisor these become
    /// `--uid-map` args to the bundled virtiofsd; under libkrun they go to
    /// `krun_add_virtiofs4`. `gid_map` is the same for GIDs.
    #[serde(default)]
    pub uid_map: Vec<String>,
    #[serde(default)]
    pub gid_map: Vec<String>,
}

/// Drop windows that do not fit the guest's DAX span so the agent receives only usable tags.
///
/// Match libkrun's placement within [`DAX_TOTAL_MAX`]: PCI memory BARs require power-of-two
/// sizes and bases aligned to those sizes. Naming a share without a window in
/// `VIRTKIT_VIRTIOFS_DAX` causes a refused `dax=always` mount on every boot. Shares that
/// do not fit use slower ordinary mounts without failing the boot.
pub fn apply_dax_budget(shares: &mut [FsShare], mem: &str) {
    // A guest whose RAM reaches into the span is given no span at all, so every window is
    // refused rather than the ones past the ceiling. An unparseable size is a
    // cloud-hypervisor one, where no share has a window to lose.
    if crate::run::parse_mem_mib(mem).is_some_and(|mib| mib > DAX_MAX_GUEST_MIB) {
        if shares.iter().any(|s| s.dax.is_some()) {
            eprintln!(
                "virtkit: a guest with more than {} GiB of RAM has no room for DAX windows; \
                 serving its virtio-fs shares without one",
                DAX_MAX_GUEST_MIB >> 10
            );
        }
        for share in shares.iter_mut() {
            share.dax = None;
        }
        return;
    }
    let mut next = 0u64;
    for share in shares.iter_mut() {
        let Some(window) = share.dax else { continue };
        let placed = window
            .checked_next_power_of_two()
            .map(|size| size.max(DAX_MIN))
            .and_then(|size| Some((size, next.checked_next_multiple_of(size)?)))
            .and_then(|(size, base)| base.checked_add(size))
            .filter(|end| *end <= DAX_TOTAL_MAX);
        match placed {
            Some(end) => next = end,
            None => {
                eprintln!(
                    "virtkit: virtio-fs share {:?} would take the guest past its {} GiB of \
                     DAX window space; serving it without one",
                    share.tag,
                    DAX_TOTAL_MAX >> 30
                );
                share.dax = None;
            }
        }
    }
}

/// Guest networking outside the switch: a host tap by name (CI `net.mode = tap|pool`), or
/// nothing. Switch-mode guests use [`Net::None`] here and attach through [`switch_attach`]
/// — [`VmSpec::nics`] under libkrun, a vsock bridge under cloud-hypervisor.
#[derive(serde::Serialize, serde::Deserialize)]
pub enum Net {
    None,
    Tap { tap: String, mac: String },
}

/// A libkrun virtio-net device backed by one switch-port unix stream. The switch natively
/// speaks its qemu/passt framing: a 4-byte big-endian length followed by one ethernet frame.
/// Attached with `krun_add_net_unixstream`; cloud-hypervisor uses the vsock/tap path in
/// [`switch_attach`] instead. Attach order sets interface order.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Nic {
    pub socket: PathBuf,
    /// `aa:bb:cc:dd:ee:ff`, the switch's per-MAC identity for this NIC ([`mac_for_ip`]).
    pub mac: String,
}

/// How one guest joins the switch, in the form the VMM and the guest agent each read.
/// Built by [`switch_attach`]; the caller appends `cmdline` to the guest's and folds the
/// devices into its [`VmSpec`] with [`SwitchAttach::apply`].
pub struct SwitchAttach {
    pub vsock_ports: Vec<VsockPort>,
    pub nics: Vec<Nic>,
    pub cmdline: String,
}

impl SwitchAttach {
    /// Append any vsock bridges and return the [`VmSpec::nics`]. Only one collection is
    /// populated, so callers need not branch on the backend.
    pub fn apply(self, vsock_ports: &mut Vec<VsockPort>) -> Vec<Nic> {
        vsock_ports.extend(self.vsock_ports);
        self.nics
    }
}

/// Wire a guest's NICs to the switch ports `net_port + i`, one per address in `addrs`
/// (eth0's first, then each NIC after it in interface order; all share `prefix`). The
/// switch must already listen on `hybrid_socket(vsock, net_port + i)` for each.
///
/// Under libkrun, each socket backs a [`Nic`]; `net.ifnames=0` preserves `eth<i>`, and
/// `VIRTKIT_NET_VIRTIO=1` tells the agent only to address it. Under cloud-hypervisor, the
/// agent creates one tap per NIC and bridges it over `VIRTKIT_NET_PORT`. Both paths use the
/// same static address, gateway, and resolver tokens. Address-derived MACs match the
/// switch's per-MAC reservation to the same IP.
///
/// `libkrun` is the selected backend: every boot site passes [`libkrun_selected`], and it
/// is a parameter only because that reads process-global state a test cannot set.
///
/// `net_port + i` is unchecked here, unlike the guest side's: `net_port` is the host's own
/// (`[net] net_port`, or the `vk run` constant) and the same sum already named the sockets
/// the switch was told to listen on, so a value that overflowed would have failed to bind
/// long before a guest saw it.
pub fn switch_attach(
    vsock: &Path,
    net_port: u32,
    addrs: &[std::net::Ipv4Addr],
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    libkrun: bool,
) -> SwitchAttach {
    let mut out = SwitchAttach {
        vsock_ports: Vec::new(),
        nics: Vec::new(),
        cmdline: String::new(),
    };
    let Some((eth0, extra)) = addrs.split_first() else {
        return out;
    };
    if libkrun {
        for (i, ip) in addrs.iter().enumerate() {
            out.nics.push(Nic {
                socket: hybrid_socket(vsock, net_port + i as u32),
                mac: mac_for_ip(*ip),
            });
        }
        out.cmdline
            .push_str(" VIRTKIT_NET_VIRTIO=1 net.ifnames=0 biosdevname=0");
    } else {
        for i in 0..addrs.len() as u32 {
            out.vsock_ports.push(VsockPort::bridge(vsock, net_port + i));
        }
        out.cmdline.push_str(&format!(
            " VIRTKIT_NET_PORT={net_port} VIRTKIT_VM_MAC={}",
            mac_for_ip(*eth0)
        ));
    }
    out.cmdline.push_str(&format!(
        " VIRTKIT_VM_IP={eth0}/{prefix} VIRTKIT_VM_GW={gateway} VIRTKIT_VM_DNS={gateway}"
    ));
    if let Some(extra) = net_extra_ips_env(extra, prefix) {
        out.cmdline.push_str(&extra);
    }
    out
}

/// The `VIRTKIT_NET_EXTRA_IPS` cmdline fragment for a guest's NICs after eth0: each address
/// as `ip/prefix`, comma-joined in interface order — the spelling `vk-agent` splits back
/// apart. `None` (no fragment) when eth0 is the only NIC.
fn net_extra_ips_env(extra_ips: &[std::net::Ipv4Addr], prefix: u8) -> Option<String> {
    if extra_ips.is_empty() {
        return None;
    }
    let specs: Vec<String> = extra_ips
        .iter()
        .map(|ip| format!("{ip}/{prefix}"))
        .collect();
    Some(format!(" VIRTKIT_NET_EXTRA_IPS={}", specs.join(",")))
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
    /// Switch-mode NICs as virtio-net devices (libkrun; see [`switch_attach`]). Empty for
    /// cloud-hypervisor, whose switch guests ride a vsock bridge in `vsock_ports` instead.
    #[serde(default)]
    pub nics: Vec<Nic>,
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
    /// Reboot the VM in place on a guest reset instead of ending the process. The
    /// libkrun boot child ([`crate::libkrun_sys::keep`]) then relaunches the VM on the
    /// same disks, keeping its pid and vsock socket. Set for long-lived guests (compose
    /// services, `vk run` sessions); left off for build/job VMs, which end on reset.
    #[serde(default)]
    pub reboot: bool,
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
        // `nics` is a libkrun-only attach; the boot sites build a cloud-hypervisor spec
        // with the vsock bridge instead (`switch_attach(.., libkrun = false)`), so a
        // populated list here is a caller bug, not a configuration a user can reach.
        debug_assert!(
            spec.nics.is_empty(),
            "cloud-hypervisor attaches the switch over vsock, not as virtio-net devices"
        );
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
    fn switch_attach_libkrun_is_one_nic_per_port_addressed_from_the_cmdline() {
        let vsock = Path::new("/w/vsock.sock");
        let gw: std::net::Ipv4Addr = "192.168.127.1".parse().unwrap();
        let addrs: Vec<std::net::Ipv4Addr> = ["192.168.127.2", "192.168.127.254"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let a = switch_attach(vsock, 1024, &addrs, 24, gw, true);
        // No vsock bridge: the NICs are virtio-net devices on the switch's per-port
        // sockets, eth0 on 1024 and eth1 on 1025, each with its address-derived MAC.
        assert!(a.vsock_ports.is_empty());
        let nics: Vec<(String, String)> = a
            .nics
            .iter()
            .map(|n| (n.socket.display().to_string(), n.mac.clone()))
            .collect();
        assert_eq!(
            nics,
            vec![
                (
                    "/w/vsock.sock_1024".to_string(),
                    "52:54:00:a8:7f:02".to_string()
                ),
                (
                    "/w/vsock.sock_1025".to_string(),
                    "52:54:00:a8:7f:fe".to_string()
                ),
            ]
        );
        // The agent addresses what the kernel brought up; `net.ifnames=0` keeps an image's
        // systemd from renaming eth0 under it.
        assert_eq!(
            a.cmdline,
            " VIRTKIT_NET_VIRTIO=1 net.ifnames=0 biosdevname=0 \
             VIRTKIT_VM_IP=192.168.127.2/24 VIRTKIT_VM_GW=192.168.127.1 \
             VIRTKIT_VM_DNS=192.168.127.1 VIRTKIT_NET_EXTRA_IPS=192.168.127.254/24"
        );
    }

    #[test]
    fn switch_attach_cloud_hypervisor_bridges_each_nic_over_vsock() {
        let vsock = Path::new("/w/vsock.sock");
        let gw: std::net::Ipv4Addr = "192.168.127.1".parse().unwrap();
        let addrs: Vec<std::net::Ipv4Addr> = ["192.168.127.2", "192.168.127.254"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let a = switch_attach(vsock, 1024, &addrs, 24, gw, false);
        // One guest→host bridge per NIC on 1024 + the interface index, no virtio device;
        // the agent forks a tap per NIC, eth0's with the run-assigned MAC.
        assert!(a.nics.is_empty());
        let ports: Vec<(u32, String, bool)> = a
            .vsock_ports
            .iter()
            .map(|p| (p.port, p.socket.display().to_string(), p.listen))
            .collect();
        assert_eq!(
            ports,
            vec![
                (1024, "/w/vsock.sock_1024".to_string(), false),
                (1025, "/w/vsock.sock_1025".to_string(), false),
            ]
        );
        assert_eq!(
            a.cmdline,
            " VIRTKIT_NET_PORT=1024 VIRTKIT_VM_MAC=52:54:00:a8:7f:02 \
             VIRTKIT_VM_IP=192.168.127.2/24 VIRTKIT_VM_GW=192.168.127.1 \
             VIRTKIT_VM_DNS=192.168.127.1 VIRTKIT_NET_EXTRA_IPS=192.168.127.254/24"
        );
    }

    #[test]
    fn switch_attach_degenerate_nic_counts() {
        let vsock = Path::new("/w/vsock.sock");
        let gw: std::net::Ipv4Addr = "192.168.127.1".parse().unwrap();
        let eth0: std::net::Ipv4Addr = "192.168.127.2".parse().unwrap();
        // eth0 alone carries no VIRTKIT_NET_EXTRA_IPS, on either backend.
        for libkrun in [true, false] {
            let one = switch_attach(vsock, 1024, &[eth0], 24, gw, libkrun);
            assert!(!one.cmdline.contains("VIRTKIT_NET_EXTRA_IPS"));
            assert_eq!(one.nics.len() + one.vsock_ports.len(), 1);
        }
        // No address at all attaches nothing and says nothing on the cmdline: `--net` is
        // off, and a guest with no port on the switch must not be told it has one.
        for libkrun in [true, false] {
            let none = switch_attach(vsock, 1024, &[], 24, gw, libkrun);
            assert!(none.nics.is_empty());
            assert!(none.vsock_ports.is_empty());
            assert!(none.cmdline.is_empty());
        }
    }

    #[test]
    fn switch_attach_apply_moves_the_devices_into_the_boot() {
        let vsock = Path::new("/w/vsock.sock");
        let gw: std::net::Ipv4Addr = "192.168.127.1".parse().unwrap();
        let addrs: Vec<std::net::Ipv4Addr> = ["192.168.127.2", "192.168.127.254"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        // A boot site starts from its own ports (here the exec channel) and folds the
        // attach in: under libkrun that adds NICs and no port, under cloud-hypervisor one
        // bridge per NIC and no NIC. Either way the site's own ports keep their place.
        let mut ports = vec![VsockPort::exec(vsock, 4444)];
        let nics = switch_attach(vsock, 1024, &addrs, 24, gw, true).apply(&mut ports);
        assert_eq!(nics.len(), 2);
        assert_eq!(ports.iter().map(|p| p.port).collect::<Vec<_>>(), vec![4444]);

        let mut ports = vec![VsockPort::exec(vsock, 4444)];
        let nics = switch_attach(vsock, 1024, &addrs, 24, gw, false).apply(&mut ports);
        assert!(nics.is_empty());
        assert_eq!(
            ports.iter().map(|p| p.port).collect::<Vec<_>>(),
            vec![4444, 1024, 1025]
        );
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

    /// Detect new qcow2 and legacy raw volume formats; reject lazy chunk views.
    #[test]
    fn for_image_attaches_by_sniffed_format_and_refuses_a_chunk_view() {
        let dir = std::env::temp_dir().join(format!("vk-for-image-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Raw ext4 has no leading magic because its superblock starts at offset 1024. Attach
        // it without Cloud Hypervisor image-type or backing-file keys for compatibility.
        let raw = dir.join("old.ext4");
        std::fs::write(&raw, [0u8; 4096]).unwrap();
        let d = Disk::for_image(raw, false).unwrap();
        assert!(d.format == DiskFormat::Raw, "a zero-magic file is raw");
        assert!(!d.ch_value().contains("image_type"), "{}", d.ch_value());

        // A new volume sniffs as qcow2 and takes the Cloud Hypervisor qcow2 path. It has no
        // backing chain, so backing_files=on is a no-op.
        let q = dir.join("vol.qcow2");
        crate::qcow2::Qcow2Writer::create(&q, 1 << 20, 0o600)
            .unwrap()
            .finish()
            .unwrap();
        let d = Disk::for_image(q, true).unwrap();
        assert!(d.format == DiskFormat::Qcow2, "the qcow2 magic is qcow2");
        assert!(
            d.ch_value().contains("image_type=qcow2,backing_files=on"),
            "{}",
            d.ch_value()
        );

        // A lazy manifest is a chunk view, not a disk, and must not fall back to raw.
        let lazy = dir.join("view.vk_ro_img");
        let mut bytes = crate::registry::VK_RO_IMG_MAGIC.to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        std::fs::write(&lazy, bytes).unwrap();
        let err = Disk::for_image(lazy, false)
            .err()
            .expect("a chunk view is refused");
        assert!(format!("{err:#}").contains("not a disk"), "{err:#}");

        std::fs::remove_dir_all(&dir).unwrap();
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

    #[test]
    fn dax_policy_parses_sizes_and_the_spellings_of_off() {
        use std::str::FromStr;
        assert_eq!(Dax::from_str("8G").unwrap(), Dax::Window(8 << 30));
        assert_eq!(Dax::from_str("512M").unwrap(), Dax::Window(512 << 20));
        // A bare count is MiB, like every other size this CLI takes.
        assert_eq!(Dax::from_str("64").unwrap(), Dax::Window(64 << 20));
        // What a YAML or TOML scalar turns "no" into all mean off.
        for off in ["off", "false", "0", "no", " off "] {
            assert_eq!(Dax::from_str(off).unwrap(), Dax::Off, "{off}");
        }
        // Under one FUSE DAX range the window could hold no mapping at all.
        assert!(Dax::from_str("1M").is_err());
        assert!(Dax::from_str("lots").is_err());
        // Past the guest's whole span there is nowhere to put it: refused here rather than
        // taken and then silently dropped at boot.
        assert!(Dax::from_str("128G").is_err());
        assert_eq!(
            Dax::from_str(&format!("{}G", DAX_TOTAL_MAX >> 30)).unwrap(),
            Dax::Window(DAX_TOTAL_MAX)
        );
        // Round-trips through the config file, which stores the policy as a string.
        assert_eq!(DAX_DEFAULT.to_string(), "8G");
        assert_eq!(Dax::Window(512 << 20).to_string(), "512M");
        assert_eq!(
            Dax::from_str(&DAX_DEFAULT.to_string()).unwrap(),
            DAX_DEFAULT
        );
        assert_eq!(Dax::Off.to_string(), "off");
        assert_eq!(Dax::Off.window(), None);
        assert_eq!(DAX_DEFAULT.window(), Some(8 << 30));
    }

    fn dax_share(tag: &str, dax: Option<u64>) -> FsShare {
        FsShare {
            tag: tag.into(),
            socket: PathBuf::new(),
            host_dir: PathBuf::new(),
            read_only: false,
            dax,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        }
    }

    #[test]
    fn the_dax_budget_drops_the_windows_that_do_not_fit() {
        // Eight default windows fill the span exactly; the ninth gets none, and a share
        // that asked for nothing is charged nothing.
        let mut shares: Vec<FsShare> = (0..9)
            .map(|i| dax_share(&format!("s{i}"), DAX_DEFAULT.window()))
            .collect();
        shares.push(dax_share("atop", None));
        apply_dax_budget(&mut shares, "4G");
        assert!(shares[..8].iter().all(|s| s.dax == DAX_DEFAULT.window()));
        assert_eq!(shares[8].dax, None);
        assert_eq!(shares[9].dax, None);
    }

    #[test]
    fn the_dax_budget_charges_what_libkrun_will_actually_place() {
        // libkrun rounds a window up to a power of two at a base aligned to it, so a 3G
        // request occupies 4G: sixteen fit in the span, not the twenty a raw sum allows.
        let mut shares: Vec<FsShare> = (0..20)
            .map(|i| dax_share(&format!("s{i}"), Some(3 << 30)))
            .collect();
        apply_dax_budget(&mut shares, "4G");
        assert_eq!(shares.iter().filter(|s| s.dax.is_some()).count(), 16);
        // The alignment is what keeps this cursor equal to libkrun's; it cannot change how
        // many fit, since every charged size and the span itself are powers of two, so the
        // gap an alignment leaves is always smaller than the window that follows it.
        let mut shares = vec![dax_share("small", Some(2 << 20))];
        shares.extend((0..8).map(|i| dax_share(&format!("s{i}"), Some(8 << 30))));
        apply_dax_budget(&mut shares, "4G");
        assert_eq!(shares.iter().filter(|s| s.dax.is_some()).count(), 8);
        assert_eq!(shares.last().unwrap().dax, None);
    }

    /// A guest whose RAM reaches the span's base is given no span, so telling its agent
    /// about a window would earn a refused mount on every boot.
    #[test]
    fn a_guest_too_large_for_the_span_gets_no_windows_at_all() {
        let shares = || vec![dax_share("work", DAX_DEFAULT.window())];
        let mut s = shares();
        apply_dax_budget(&mut s, &format!("{DAX_MAX_GUEST_MIB}M"));
        assert_eq!(s[0].dax, DAX_DEFAULT.window());
        let mut s = shares();
        apply_dax_budget(&mut s, &format!("{}M", DAX_MAX_GUEST_MIB + 1));
        assert_eq!(s[0].dax, None);
        // A size this parser does not know is cloud-hypervisor's, where no share has a
        // window to lose anyway.
        let mut s = shares();
        apply_dax_budget(&mut s, "64G@0");
        assert_eq!(s[0].dax, DAX_DEFAULT.window());
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
                dax: None,
                uid_map: Vec::new(),
                gid_map: Vec::new(),
            }],
            vsock_cid: 3,
            vsock_socket: "/job/vsock.sock".into(),
            vsock_ports: vec![],
            cpus: 4,
            mem: "8G".into(),
            shared_mem: true,
            nics: Vec::new(),
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
            reboot: false,
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
            nics: Vec::new(),
            net: Net::None,
            balloon: false,
            serial_log: "/w/console.log".into(),
            console_serial: false,
            pmu: false,
            nested: false,
            api_socket: None,
            pass_fds: Vec::new(),
            proc_name: "vk:build".into(),
            reboot: false,
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
