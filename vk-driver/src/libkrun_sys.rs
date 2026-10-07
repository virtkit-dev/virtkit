//! libkrun backend: the boot child builds a [`VmSpec`] into a VM through libkrun's Rust API
//! (`VmmBuilder`, a `Payload` and typed devices) and runs it in this process. libkrun is the
//! vendored `krun` rlib crate (third_party/libkrun), so it shares virtkit's std.
//!
//! libkrun runs as a per-VM subprocess (the [`crate::vmm::Libkrun`] impl re-execs this
//! binary with the spec in `VIRTKIT_BOOT_SPEC`), so the orchestrator manages it like any
//! other child — held `Child` / `spawn_tied`, no in-process VMM in the orchestrator. We
//! always supply our own kernel, so libkrun never loads libkrunfw.
//!
//! Boots a disk/initramfs guest with our kernel + cmdline-`init=` (PID 1): virtio-blk disks
//! (qcow2 backing chains), built-in virtio-fs shares, per-port vsock, switch NICs as
//! unixstream-backed virtio-net devices, optional tap networking, and the console on the
//! serial-log file. Devices sit on virtio-pci with MSI-X behind an ACPI host bridge.
//!
//! [`boot`] never returns once the guest runs: libkrun `_exit`s with its code. A host SIGTERM
//! presses the guest's ACPI power button: SIGTERM is blocked before any thread exists and a
//! dedicated thread waits for it and calls `VmmHandle::shutdown`, so nothing runs in a signal
//! handler. When the spec allows reboot, [`keep`] wraps the boot in a relaunch loop so a guest
//! reset (`KRUN_EXIT_GUEST_RESET`) reboots the VM in place — same pid and vsock socket for the
//! supervisor.

use std::fs::{File, OpenOptions};
use std::os::fd::{AsFd, BorrowedFd, IntoRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use krun::{
    AttachDevice, BalloonDevice, BlockDevice, ConsoleDevice, DiskFormat, FsCachePolicy, FsDevice,
    KRUN_EXIT_GUEST_RESET, KernelFormat, LogLevel, LogOptions, LogStyle, MmioDeviceManager,
    NetDevice, NetFlags, Payload, PciDeviceManager, RngDevice, SyncMode, TsiFlags, VmmBuilder,
    VmmError, VmmHandle, VsockDevice, port_io,
};
use vk_core::unixpath::SocketPath;

use crate::vmm::{Disk, DiskSync, FsShare, Net, VmSpec};

/// The `KernelFormat` libkrun should load `data` (a kernel image) as. A raw ELF `vmlinux` is
/// `Elf`; anything else is treated as an "Image" whose payload libkrun decompresses then
/// ELF-loads — so we return the format of the compression whose magic appears EARLIEST,
/// mirroring libkrun's own first-occurrence scan (a stock `bzImage` carries its real payload
/// after the boot setup, and the earliest magic is that payload). Returns `None` for a format
/// libkrun can't load (e.g. xz/lz4, or a raw uncompressed non-ELF), so the caller can point the
/// user at `scripts/extract-vmlinux`.
fn detect_kernel_format(data: &[u8]) -> Option<KernelFormat> {
    if data.starts_with(b"\x7fELF") {
        return Some(KernelFormat::Elf);
    }
    let first = |needle: &[u8]| data.windows(needle.len()).position(|w| w == needle);
    [
        (first(&[0x28, 0xb5, 0x2f, 0xfd]), KernelFormat::ImageZstd), // zstd
        (first(&[0x1f, 0x8b, 0x08]), KernelFormat::ImageGz),         // gzip
        (first(b"BZh"), KernelFormat::ImageBz2),                     // bzip2
    ]
    .into_iter()
    .filter_map(|(pos, fmt)| pos.map(|p| (p, fmt)))
    .min_by_key(|&(p, _)| p)
    .map(|(_, fmt)| fmt)
}

/// Normalise the guest cmdline's console token. The embedded kernel has virtio_console built
/// in (hvc0) from early boot, so by default the cmdline's `console=ttyS0` is rewritten to
/// `console=hvc0` (the safe, pre-patch behaviour). A BYO/stock distro kernel has
/// virtio_console as a module and only emits early output on the legacy serial, so
/// `keep_serial` (`vk run --console-serial`) leaves `console=ttyS0` in place, served by the
/// legacy COM1 serial `boot` adds.
fn console_cmdline(cmdline: &str, keep_serial: bool) -> String {
    if keep_serial {
        cmdline.to_string()
    } else {
        cmdline.replace("console=ttyS0", "console=hvc0")
    }
}

/// The format of the kernel at `path`, or a clear error if libkrun cannot
/// load it. Reads the file to sniff its magic (the same bytes libkrun itself scans).
fn kernel_format(path: &Path) -> Result<KernelFormat> {
    let data = std::fs::read(path).with_context(|| format!("reading kernel {}", path.display()))?;
    detect_kernel_format(&data).with_context(|| {
        format!(
            "unsupported kernel {}: libkrun boots an ELF vmlinux or a gzip/zstd/bzip2-compressed \
             bzImage. For an xz/lz4-compressed or otherwise unrecognized image, supply the ELF \
             vmlinux (e.g. via the kernel tree's `scripts/extract-vmlinux`).",
            path.display()
        )
    })
}

/// Parse a memory size token into MiB for `VmmBuilder::ram_mib`, accepting the same
/// forms as the CLI (`<n>G`, `<n>M`, plain MiB — see
/// `run::parse_mem_mib`).
fn mem_mib(mem: &str) -> Result<u32> {
    crate::run::parse_mem_mib(mem)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| anyhow::anyhow!("memory size {mem:?} is not <n>G, <n>M or a MiB count"))
}

/// The guest's vsock CID: 3, the one vk's guests have always had.
const GUEST_CID: u64 = 3;

/// How long the guest gets to act on the power button before the boot child ends the VM
/// itself, disks flushed: a backstop for a guest that ignores it after `vk` is gone. It
/// outlasts the longest grace `vk` gives, a Windows build step's ten minutes
/// (`uefi::BUILD_STOP_GRACE`), so that `vk` ends the VM itself whenever it is there to.
const POWER_BUTTON_GRACE: Duration = Duration::from_secs(11 * 60);

/// How long the VM has to flush its disks and exit once the backstop ends it, before the boot
/// child exits anyway.
const QUIT_BACKSTOP: Duration = Duration::from_secs(10);

/// The drive letter of the `index`th disk (`a` for vda), refused past `z`.
fn disk_letter(index: usize) -> Result<char> {
    u8::try_from(index)
        .ok()
        .and_then(|i| b'a'.checked_add(i))
        .filter(u8::is_ascii_lowercase)
        .map(char::from)
        .with_context(|| format!("too many disks: no virtio-blk letter for disk {index}"))
}

/// The transport the devices sit on: virtio-pci with MSI-X, or virtio-mmio under
/// `VIRTKIT_KRUN_MMIO=1` (to rule the transport out when debugging).
enum Devices<'a> {
    Mmio(MmioDeviceManager<'a>),
    Pci(PciDeviceManager<'a>),
}

impl<'a> Devices<'a> {
    fn new() -> Self {
        if std::env::var("VIRTKIT_KRUN_MMIO").as_deref() == Ok("1") {
            Devices::Mmio(MmioDeviceManager::new())
        } else {
            Devices::Pci(PciDeviceManager::new())
        }
    }

    fn add(&mut self, device: impl AttachDevice<'a>) {
        match self {
            Devices::Mmio(m) => {
                m.add(device);
            }
            Devices::Pci(p) => {
                p.add(device);
            }
        }
    }

    fn attach(self, builder: VmmBuilder<'a>) -> VmmBuilder<'a> {
        match self {
            Devices::Mmio(m) => builder.devices(m),
            Devices::Pci(p) => builder.devices(p),
        }
    }
}

/// A libkrun error as an `anyhow` one, naming what was being set up.
fn krun(what: &'static str) -> impl FnOnce(VmmError) -> anyhow::Error {
    move |e| anyhow!("libkrun: {what}: {e}")
}

/// `path` as the `&str` libkrun's builders take.
fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

/// Boot `spec` under libkrun in this process. Returns only if setup fails; once the
/// guest runs, libkrun ends the process with its exit code.
fn boot(spec: &VmSpec, tap_fd: Option<&OwnedFd>, restore: bool) -> Result<()> {
    // Before any thread exists, so every thread libkrun spawns inherits the mask and the
    // signal stays pending for the power-button thread.
    block_sigterm();
    set_process_name(&spec.proc_name);

    // libkrun logs to stderr (captured to the VMM log). Debug fires on the block and
    // virtio-fs I/O paths and slows a build, so only under VIRTKIT_DEBUG=1.
    let level = if std::env::var("VIRTKIT_DEBUG").as_deref() == Ok("1") {
        LogLevel::Debug
    } else {
        LogLevel::Warn
    };
    krun::init_log(None, level, LogStyle::Auto, LogOptions::empty()).map_err(krun("logging"))?;

    // qemu-ga's port for an agent-less guest: libkrun dups one socketpair end; the other
    // is relayed to the spec's socket. Created before the devices, which borrow it.
    let guest_agent = match &spec.guest_agent {
        Some(socket) => {
            let (port, host) =
                std::os::unix::net::UnixStream::pair().context("guest agent socketpair")?;
            crate::relay::serve_agent_socket(socket, host, "vk-qga")?;
            Some(port)
        }
        None => None,
    };
    // COM1's input for `vk console`: one socketpair end goes to libkrun, which takes
    // ownership of a serial console's fd when the VM is built; the other is relayed to the
    // spec's socket.
    let serial_input = match &spec.serial_input {
        Some(socket) => {
            let (port, host) =
                std::os::unix::net::UnixStream::pair().context("serial input socketpair")?;
            crate::relay::serve_socket(socket, host, "vk-console")?;
            // SAFETY: the fd is open and, once released here, owned by libkrun alone.
            Some(unsafe { BorrowedFd::borrow_raw(port.into_raw_fd()) })
        }
        None => None,
    };
    // libkrun binds and dials these sockets once the VM runs, a vsock port's peer only on
    // the guest's first connect, so they are held until the process ends.
    let mut sockets = Vec::new();
    let mut devices = Devices::new();

    // Send hvc0 and legacy COM1 to the serial log for orchestrator diagnostics.
    // COM1 covers modular virtio_console (`vk run --console-serial`, an image kernel).
    // Leak the file: libkrun borrows it for COM1 throughout the VM's lifetime.
    let log: &'static File = Box::leak(Box::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&spec.serial_log)
            .with_context(|| format!("opening serial log {}", spec.serial_log.display()))?,
    ));
    let mut console = ConsoleDevice::builder();
    console.add_console_port(
        "",
        port_io::output_file(log.try_clone().context("duplicating the serial log")?)
            .map_err(|e| anyhow!("libkrun: console output: {e}"))?,
    );
    if let Some(port) = &guest_agent {
        console
            .add_inout_port(
                crate::qga::PORT_NAME,
                Some(port.as_fd()),
                Some(port.as_fd()),
            )
            .map_err(krun("guest agent port"))?;
    }
    devices.add(console.build().map_err(krun("console"))?);

    for (i, disk) in spec.disks.iter().enumerate() {
        devices.add(block_device(i, disk, &mut sockets)?);
    }
    for share in &spec.shares {
        devices.add(fs_device(share)?);
    }
    match &spec.net {
        Net::None => {}
        Net::Tap { mac, .. } => {
            let mac =
                crate::switch::parse_mac(mac).ok_or_else(|| anyhow!("invalid MAC {mac:?}"))?;
            let fd = tap_fd
                .context("tap not attached before boot")?
                .try_clone()
                .context("duplicating the tap descriptor")?;
            devices.add(NetDevice::new_tap_fd("eth0", fd, &mac, 0).map_err(krun("tap NIC"))?);
        }
    }
    // Switch NICs: one virtio-net device per switch port, dialing the socket the switch
    // listens on and speaking its 4-byte-length framing, with no offloads (the switch
    // terminates TCP and wants complete checksums) and the switch LAN's MTU, so the guest
    // link comes up at it unconfigured. Attach order is interface order (eth0, eth1, …),
    // after a tap's eth0 when there is one; the ids follow it, libkrun keying devices by id.
    let first = usize::from(matches!(spec.net, Net::Tap { .. }));
    for (i, nic) in spec.nics.iter().enumerate() {
        let socket = SocketPath::new(&nic.socket)
            .with_context(|| format!("switch nic {i}: socket {}", nic.socket.display()))?;
        let mac = crate::switch::parse_mac(&nic.mac)
            .ok_or_else(|| anyhow!("switch nic {i}: invalid MAC {:?}", nic.mac))?;
        let mut net = NetDevice::new_unixstream_path(
            &format!("eth{}", i + first),
            path_str(socket.as_path())?,
            &mac,
            0,
            NetFlags::empty(),
        )
        .map_err(krun("switch NIC"))?;
        net.set_mtu(crate::switch::MTU)
            .map_err(krun("switch NIC MTU"))?;
        devices.add(net);
        sockets.push(socket);
    }
    // vsock ports, each on its own `<base>_<port>` host socket: libkrun listens there and
    // forwards host connections to the guest port (listen), or forwards the guest's
    // connections to a host listener (the switch and ssh-agent bridges).
    // Attached only when there are ports; the agent's exec channel always is one. No TSI: a
    // job-supplied TSI-patched kernel could otherwise open, connect and listen on host
    // sockets, bypassing the switch and egress policy.
    if !spec.vsock_ports.is_empty() {
        let mut vsock = VsockDevice::new(GUEST_CID, TsiFlags::empty()).map_err(krun("vsock"))?;
        for vp in &spec.vsock_ports {
            let socket = SocketPath::new(&vp.socket).with_context(|| {
                format!("vsock port {}: socket {}", vp.port, vp.socket.display())
            })?;
            vsock.add_unix_port(vp.port, path_str(socket.as_path())?, vp.listen);
            sockets.push(socket);
        }
        devices.add(vsock);
    }
    // virtio-rng: the guest's /dev/hwrng and early entropy. Windows' virtio-net driver resets
    // its device again when it finds a virtio-rng function beside it, which needs our
    // virtio-net's reset.
    if spec.rng {
        devices.add(RngDevice::new().map_err(krun("rng"))?);
    }
    // virtio-balloon with free-page reporting; libkrun 2.0 attaches nothing implicitly.
    if spec.balloon {
        devices.add(BalloonDevice::new().map_err(krun("balloon"))?);
    }

    // Our own kernel and cmdline; PID 1 is chosen by `init=`. An image kernel
    // (VIRTKIT_KERNEL=image) is a stock modular one whose hvc0 is not up early, so it keeps
    // the legacy console, as `--console-serial` asks.
    let keep_serial = spec.console_serial
        || spec
            .cmdline
            .split_whitespace()
            .any(|t| t == "VIRTKIT_KERNEL=image");
    let cmdline = console_cmdline(&spec.cmdline, keep_serial);
    let initramfs = spec.initramfs.as_deref().map(path_str).transpose()?;
    let payload = Payload::load_external(
        path_str(&spec.kernel)?,
        kernel_format(&spec.kernel)?,
        initramfs,
        &cmdline,
    )
    .map_err(krun("kernel"))?;

    // libkrun takes a u8 vCPU count; refuse rather than wrap (`--cpus host` on a 256-core
    // machine would truncate to 0).
    let cpus: u8 = spec
        .cpus
        .try_into()
        .map_err(|_| anyhow!("libkrun supports at most 255 vCPUs (got {})", spec.cpus))?;
    let builder = VmmBuilder::new()
        .vcpus(cpus)
        .map_err(krun("vCPUs"))?
        .ram_mib(mem_mib(&spec.mem)?)
        .map_err(krun("memory"))?
        .payload(payload)
        // `vk run --pmu` (trusted guests only) and `--nested`; the host was checked for
        // nesting before this spec was handed over.
        .pmu(spec.pmu)
        .nested_virt(spec.nested)
        .hyperv(spec.hyperv)
        .map_err(krun("Hyper-V"))?
        .acpi(true)
        .map_err(krun("ACPI"))?
        .shutdown_support(true)
        .add_serial_console(serial_input, Some(log.as_fd()))
        .map_err(krun("serial console"))?
        .vm_generation_id(spec.vm_generation_id)
        .map_err(krun("VM generation ID"))?;
    let builder = match spec.restore_from.as_ref().filter(|_| restore) {
        Some(dir) => builder.restore_from(dir.clone()),
        None => builder,
    };
    let builder = match spec.system_uuid {
        Some(uuid) => builder.system_uuid(uuid),
        None => builder,
    };
    let builder = match &spec.uefi_vars {
        Some(path) => builder.uefi_vars(path.clone()),
        None => builder,
    };
    let builder = match &spec.tpm_state {
        Some(path) => builder.tpm_state(path.clone()),
        None => builder,
    };
    let vmm = devices
        .attach(builder)
        .build()
        .map_err(krun("building the VM"))?;
    let handle = vmm.handle().map_err(krun("VM handle"))?;
    if let Some(socket) = &spec.control {
        crate::vmmctl::serve(socket, handle.clone())?;
    }
    press_power_button_on_sigterm(handle)?;

    // Blocks until the guest powers off or resets; libkrun `_exit`s with its code. It returns
    // only when the event loop fails, which must not read as a clean power-off.
    vmm.run();
    drop(sockets);
    bail!("libkrun: the VM event loop ended before the guest exited")
}

fn block_device(index: usize, disk: &Disk, sockets: &mut Vec<SocketPath>) -> Result<BlockDevice> {
    let id = format!("vd{}", disk_letter(index)?);
    let format = match disk.format {
        crate::vmm::DiskFormat::Raw => DiskFormat::Raw,
        crate::vmm::DiskFormat::Qcow2 => DiskFormat::Qcow2,
        crate::vmm::DiskFormat::VkLazyChunks => DiskFormat::VkLazyChunks,
    };
    let mut block =
        BlockDevice::new(&id, path_str(&disk.path)?, format).map_err(krun("block device"))?;
    block.set_read_only(disk.readonly);
    // The host page cache (no direct I/O), and the disk's FLUSH handling: a throwaway
    // overlay offers the guest none.
    block.set_sync_mode(match disk.sync {
        DiskSync::Full => SyncMode::Full,
        DiskSync::None => SyncMode::None,
    });
    // Dirty-cluster tracking (build stages): a checkpoint drains only its delta.
    if let Some(path) = &disk.dirty_control_socket {
        let socket = SocketPath::new(path)
            .with_context(|| format!("{id}: dirty-control socket {}", path.display()))?;
        block.set_dirty_control_socket(path_str(socket.as_path())?);
        sockets.push(socket);
    }
    Ok(block)
}

fn fs_device(share: &FsShare) -> Result<FsDevice<'static>> {
    let dir = path_str(&share.host_dir)?;
    let mut fs = if share.read_only {
        FsDevice::new_read_only(&share.tag, dir)
    } else {
        FsDevice::new(&share.tag, dir)
    }
    .map_err(krun("virtio-fs share"))?;
    fs.set_id_maps(share.uid_map.clone(), share.gid_map.clone());
    // The DAX window is guest address space reserved above RAM; `vmm::apply_dax_budget`
    // already dropped the windows the guest's span cannot place. With a floor, the guest
    // mounts `dax=inode` and maps only regular files at least that large.
    if let Some(dax) = share.dax {
        fs.set_dax_window_size(dax.window);
        fs.set_dax_inode_min(dax.inode_min)
            .map_err(krun("virtio-fs DAX"))?;
    }
    let (entry, attr, negative) = share.cache.timeouts_ms();
    let ms = |ms: u32| Duration::from_millis(ms.into());
    fs.set_cache(
        if share.cache.caches_always() {
            FsCachePolicy::Always
        } else {
            FsCachePolicy::Auto
        },
        ms(entry),
        ms(attr),
        ms(negative),
    )
    .map_err(krun("virtio-fs cache"))?;
    fs.set_xattr(share.cache.xattr())
        .map_err(krun("virtio-fs xattr"))?;
    fs.set_writeback(share.cache.writeback())
        .map_err(krun("virtio-fs writeback"))?;
    fs.set_no_sync(share.cache.no_sync())
        .map_err(krun("virtio-fs no_sync"))?;
    Ok(fs)
}

/// Name the process after its VM (`vk:<unit>`, see [`crate::vmm::resolve_proc_name`]) for
/// `ps`, `top` and the tests that find a VM's VMM by its `comm`, which the kernel caps at 15
/// bytes.
fn set_process_name(name: &str) {
    let Ok(name) = std::ffi::CString::new(name) else {
        return;
    };
    // SAFETY: PR_SET_NAME reads a NUL-terminated string, truncated to 15 bytes.
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
}

/// The signals the boot child's power-button thread takes: SIGTERM (the power button) and
/// SIGUSR2 (the keeper's hard reset, [`keeper_sigusr1`]).
fn sigterm_set() -> libc::sigset_t {
    // SAFETY: sigemptyset initializes the set before sigaddset reads it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        set
    }
}

fn block_sigterm() {
    // An inherited SIG_IGN would discard SIGTERM even while blocked, so sigwait never woke.
    // SAFETY: resetting a disposition to its default has no preconditions.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGUSR2, libc::SIG_DFL);
    }
    let set = sigterm_set();
    // SAFETY: a valid set; only the calling thread's mask changes.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
}

impl crate::vmmctl::Control for VmmHandle {
    fn pause(&self) -> Result<()> {
        VmmHandle::pause(self).map_err(|e| anyhow::anyhow!("pausing the VM: {e}"))
    }

    fn resume(&self) -> Result<()> {
        VmmHandle::resume(self).map_err(|e| anyhow::anyhow!("resuming the VM: {e}"))
    }

    fn snapshot(&self, dir: &std::path::Path) -> Result<()> {
        VmmHandle::snapshot(self, dir).map_err(|e| anyhow::anyhow!("snapshotting the VM: {e}"))
    }

    fn quit(&self) -> Result<()> {
        VmmHandle::quit(self).map_err(|e| anyhow::anyhow!("ending the VM: {e}"))
    }
}

/// Handle SIGTERM on a dedicated thread: resume a paused guest and press its ACPI power button.
/// [`POWER_BUTTON_GRACE`] after the first SIGTERM, a guest still up is ended as `vk`'s
/// `force_off` ends it, through the VMM's own quit, which flushes every disk before the process
/// exits: the boot child must not outlive its parent, and a plain kill would leave a qcow2
/// overlay's cached metadata unwritten.
fn press_power_button_on_sigterm(handle: VmmHandle) -> Result<()> {
    std::thread::Builder::new()
        .name("vk-power-button".into())
        .spawn(move || {
            let set = sigterm_set();
            let mut deadline: Option<Instant> = None;
            loop {
                let sig = match deadline {
                    None => {
                        let mut sig = 0;
                        // SAFETY: a valid set, blocked in every thread; sigwait only reports
                        // which.
                        if unsafe { libc::sigwait(&set, &mut sig) } != 0 {
                            continue;
                        }
                        sig
                    }
                    Some(deadline) => {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            eprintln!(
                                "virtkit: the guest is still up {}s after the power button; \
                                 ending the VM",
                                POWER_BUTTON_GRACE.as_secs()
                            );
                            if let Err(e) = handle.quit() {
                                eprintln!("virtkit: ending the VM: {e}");
                            }
                            std::thread::sleep(QUIT_BACKSTOP);
                            // SAFETY: _exit(2) has no memory-safety preconditions.
                            unsafe { libc::_exit(1) };
                        }
                        let timeout = libc::timespec {
                            tv_sec: left.as_secs() as _,
                            tv_nsec: left.subsec_nanos() as _,
                        };
                        // SAFETY: a valid set and timespec; a null siginfo is allowed.
                        let sig =
                            unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &timeout) };
                        if sig < 0 {
                            continue;
                        }
                        sig
                    }
                };
                if sig == libc::SIGUSR2 {
                    // The keeper's hard reset: end the VM, disks flushed, for the keeper to
                    // boot it again; the keeper kills it if it lingers.
                    if let Err(e) = handle.quit() {
                        eprintln!("virtkit: ending the VM for a hard reset: {e}");
                    }
                    continue;
                }
                if sig != libc::SIGTERM {
                    continue;
                }
                // Set first: resuming waits on the event loop.
                deadline.get_or_insert_with(|| Instant::now() + POWER_BUTTON_GRACE);
                // A paused guest (`vk pause`) would not see the button; a running one is
                // left as it is.
                if let Err(e) = handle.resume() {
                    eprintln!("virtkit: resuming the VM to power it off: {e}");
                }
                if let Err(e) = handle.shutdown() {
                    eprintln!("virtkit: pressing the power button: {e}");
                }
            }
        })
        .context("spawning the power-button thread")?;
    Ok(())
}

/// Boot `spec`, relaunching the VM in place on a guest reset when `spec.reboot` is set.
///
/// Runs in the libkrun boot process (before any Tokio runtime, so `fork` is safe). The
/// forked child runs [`boot`], which execs into libkrun and never returns; this parent
/// waits for it and, on a guest reset ([`KRUN_EXIT_GUEST_RESET`]) or a host-driven hard
/// reset (SIGUSR1), boots it again. A host SIGTERM is forwarded to the child (its ACPI
/// power button) and stops the loop. Returns the process exit code to use.
pub fn keep(spec: &VmSpec) -> Result<i32> {
    // Claim the actual queue before any guest boots. Keep it across resets too: each boot
    // inherits this open description, so another VMM cannot take the tap in between.
    let tap_fd = match &spec.net {
        Net::None => None,
        Net::Tap { tap, .. } => Some(crate::net::attach_tap(tap)?),
    };
    if !spec.reboot {
        // No in-place reboot: boot once. `boot` execs libkrun and never returns on a
        // normal end (libkrun `_exit`s with the guest's code), so this is effectively
        // the whole process; a return here means setup failed before the guest ran.
        boot(spec, tap_fd.as_ref(), true)?;
        return Ok(0);
    }

    install_keeper_signals();
    let mut short_boots = 0u32;
    // A restored VM resumes from its snapshot once; a reset boots it afresh, from its disks,
    // which have moved on from the snapshot's memory since.
    let mut restore = true;
    loop {
        // Stale listen sockets from the previous boot make libkrun's vsock bind fail
        // (EEXIST). Remove exactly the ones libkrun rebinds (listen=true) — never the
        // host-owned sockets it only dials (the switch, ssh-agent bridges).
        for vp in &spec.vsock_ports {
            if vp.listen {
                // A missing socket (first boot) is the normal case, so ignore the error;
                // if it survives, the bind below fails loudly.
                let _ = std::fs::remove_file(&vp.socket);
            }
        }
        let started = Instant::now();

        // Block the keeper's signals across the fork so the child never runs the keeper's
        // handlers and the parent records the child pid before any signal is delivered.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
            bail!("fork for VM boot: {e}");
        }
        if pid == 0 {
            // Child: drop the keeper's handlers, tie our life to the keeper, unblock, boot.
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::signal(libc::SIGUSR1, libc::SIG_DFL);
                libc::signal(libc::SIGALRM, libc::SIG_DFL);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            }
            let code = match boot(spec, tap_fd.as_ref(), restore) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("virtkit: libkrun boot: {e:#}");
                    1
                }
            };
            unsafe { libc::_exit(code) };
        }

        CHILD_PID.store(pid, Ordering::SeqCst);
        unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };

        let status = wait_for(pid);
        CHILD_PID.store(0, Ordering::SeqCst);
        // SAFETY: alarm(2) has no memory-safety preconditions. Cancels a hard reset's backstop.
        unsafe { libc::alarm(0) };

        // A graceful stop (SIGTERM to the keeper) always ends the loop, whatever the child
        // reported.
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            return Ok(status.code().unwrap_or(0));
        }

        // A host-driven hard reset ends the child however it went: its own quit, or the kill
        // backing it up.
        let hard_reset = HARD_RESET.swap(false, Ordering::SeqCst);
        let reboot = match status {
            Wait::Exited(code) => hard_reset || code == i32::from(KRUN_EXIT_GUEST_RESET),
            Wait::Signaled(_) => hard_reset,
        };
        if !reboot {
            return Ok(status.code().unwrap_or(1));
        }

        // Storm guard: a guest wedged in a reboot loop must not spin forever.
        if started.elapsed() < Duration::from_secs(10) {
            short_boots += 1;
            if short_boots >= 3 {
                bail!("guest reset 3 times in under 10s — not rebooting again");
            }
        } else {
            short_boots = 0;
        }
        restore = false;
        eprintln!("virtkit: guest reset — rebooting");
    }
}

/// The current boot child's pid, for the keeper's signal handlers. 0 = none.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);
/// Set by SIGTERM: end the relaunch loop after the child stops.
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set by SIGUSR1 (hard reset): the child was ended on purpose, so relaunch it.
static HARD_RESET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// SIGTERM to the keeper: forward it to the child (its ACPI power button) and stop looping.
extern "C" fn keeper_sigterm(_sig: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
}

/// SIGUSR1 to the keeper: hard-reset — have the child end the VM through its own quit, which
/// flushes the disks the relaunch boots again (a kill would leave a qcow2 overlay's cached
/// metadata unwritten, and the next boot would corrupt it), and let the loop relaunch it. SIGALRM
/// kills the child if it is still there [`QUIT_BACKSTOP`] later.
extern "C" fn keeper_sigusr1(_sig: libc::c_int) {
    HARD_RESET.store(true, Ordering::SeqCst);
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) and alarm(2) are async-signal-safe.
        unsafe {
            libc::kill(pid, libc::SIGUSR2);
            libc::alarm(QUIT_BACKSTOP.as_secs() as libc::c_uint);
        }
    }
}

/// SIGALRM to the keeper: a hard reset's child did not end by itself; kill it.
extern "C" fn keeper_sigalrm(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

fn install_keeper_signals() {
    // SAFETY: the handlers only touch atomics and call kill(2), all async-signal-safe.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            keeper_sigterm as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGUSR1,
            keeper_sigusr1 as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGALRM,
            keeper_sigalrm as *const () as libc::sighandler_t,
        );
    }
}

/// The outcome of waiting on the boot child.
enum Wait {
    Exited(i32),
    Signaled(i32),
}

impl Wait {
    /// The process exit code to propagate: the child's own, or 128+signal.
    fn code(&self) -> Option<i32> {
        match self {
            Wait::Exited(c) => Some(*c),
            Wait::Signaled(s) => Some(128 + s),
        }
    }
}

/// `waitpid` the child, retrying across EINTR (our own signal handlers interrupt it).
fn wait_for(pid: i32) -> Wait {
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // Unwaitable child: treat as a generic failure, don't relaunch.
            return Wait::Exited(1);
        }
        if libc::WIFEXITED(status) {
            return Wait::Exited(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Wait::Signaled(libc::WTERMSIG(status));
        }
        // Stopped/continued: keep waiting.
    }
}

#[cfg(test)]
mod tests {
    use super::{KernelFormat, console_cmdline, detect_kernel_format, disk_letter, mem_mib};

    #[test]
    fn disks_are_lettered_up_to_z() {
        assert_eq!(disk_letter(0).unwrap(), 'a');
        assert_eq!(disk_letter(25).unwrap(), 'z');
        assert!(disk_letter(26).is_err());
        assert!(disk_letter(usize::MAX).is_err());
    }

    #[test]
    fn kernel_format_detection() {
        // A raw ELF vmlinux (our embedded kernel) → ELF.
        assert_eq!(
            detect_kernel_format(b"\x7fELF\x02\x01\x01"),
            Some(KernelFormat::Elf)
        );
        // A bzImage: an `MZ` PE header + boot setup, then the real compressed payload. The
        // earliest compression magic is the payload; pick its format (matching libkrun's scan).
        let mut zst = b"MZ".to_vec();
        zst.extend(std::iter::repeat_n(0u8, 4096)); // stand-in for the boot setup
        zst.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // zstd payload
        assert_eq!(detect_kernel_format(&zst), Some(KernelFormat::ImageZstd));
        let mut gz = b"MZ\x00\x00".to_vec();
        gz.extend_from_slice(&[0x1f, 0x8b, 0x08]);
        assert_eq!(detect_kernel_format(&gz), Some(KernelFormat::ImageGz));
        assert_eq!(
            detect_kernel_format(b"MZ....BZh9"),
            Some(KernelFormat::ImageBz2)
        );
        // Earliest magic wins: a real zstd payload before a spurious later gzip byte-sequence.
        let mut mixed = vec![0u8; 200];
        mixed.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // zstd first
        mixed.extend_from_slice(&[0x1f, 0x8b, 0x08]); // spurious gzip later
        assert_eq!(detect_kernel_format(&mixed), Some(KernelFormat::ImageZstd));
        // Unsupported: xz-compressed or an unrecognized blob → None (caller errors with guidance).
        assert_eq!(
            detect_kernel_format(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
            None
        );
        assert_eq!(detect_kernel_format(b"not a kernel"), None);
    }

    #[test]
    fn console_cmdline_toggle() {
        let cmdline = "init=/vk-agent console=ttyS0 root=/dev/vda";
        // Default (embedded kernel): rewrite ttyS0 -> hvc0.
        assert_eq!(
            console_cmdline(cmdline, false),
            "init=/vk-agent console=hvc0 root=/dev/vda"
        );
        // --console-serial (BYO kernel): keep ttyS0 untouched.
        assert_eq!(console_cmdline(cmdline, true), cmdline);
        // No console token present: unchanged either way.
        assert_eq!(console_cmdline("init=/vk-agent", false), "init=/vk-agent");
    }

    #[test]
    fn mem_tokens() {
        assert_eq!(mem_mib("8G").unwrap(), 8192);
        assert_eq!(mem_mib("1G").unwrap(), 1024);
        assert_eq!(mem_mib("512M").unwrap(), 512);
        assert_eq!(mem_mib("8").unwrap(), 8);
        assert!(mem_mib("lots").is_err());
    }
}
