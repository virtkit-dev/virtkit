//! libkrun 2.0 backend (the opt-in `krun2` feature): the boot child builds the VM through
//! libkrun's Rust API — `VmmBuilder`, a `Payload` and typed devices — from the vendored
//! 2.0 tree (third_party/libkrun-next). It boots the same [`VmSpec`] as the 1.19 C API in
//! [`crate::libkrun_sys`], which still drives the default build, and keeps its contract:
//! [`boot`] runs the guest in this process and never returns once it does, libkrun
//! `_exit`ing with the guest's code (154 for a reset, which [`crate::libkrun_sys::keep_with`]
//! relaunches on).
//!
//! Devices sit on virtio-mmio, described to the guest in ACPI. A host SIGTERM presses the
//! guest's ACPI power button: SIGTERM is blocked before any thread exists and a dedicated
//! thread waits for it and calls `VmmHandle::shutdown`, so nothing runs in a signal handler.

use std::fs::{File, OpenOptions};
use std::os::fd::AsFd;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use krun2::{
    BalloonDevice, BlockDevice, ConsoleDevice, DiskFormat, FsCachePolicy, FsDevice, KernelFormat,
    LogLevel, LogOptions, LogStyle, MmioDeviceManager, NetDevice, NetFlags, Payload, RngDevice,
    SyncMode, TsiFlags, VmmBuilder, VmmError, VmmHandle, VsockDevice, port_io,
};
use vk_core::unixpath::SocketPath;

use crate::libkrun_sys::{
    KRUN_KERNEL_FORMAT_ELF, KRUN_KERNEL_FORMAT_IMAGE_BZ2, KRUN_KERNEL_FORMAT_IMAGE_GZ,
    KRUN_KERNEL_FORMAT_IMAGE_ZSTD, POWER_BUTTON_GRACE_SECS, console_cmdline, disk_letter,
    kernel_format, mem_mib,
};
use crate::vmm::{Disk, DiskSync, FsShare, Net, ShareCache, VmSpec};

/// The guest's vsock CID, the one libkrun 1.19's implicit vsock device gave it.
const GUEST_CID: u64 = 3;

/// A libkrun error as an `anyhow` one, naming what was being set up.
fn krun(what: &'static str) -> impl FnOnce(VmmError) -> anyhow::Error {
    move |e| anyhow!("libkrun: {what}: {e}")
}

/// `path` as the `&str` libkrun's builders take.
fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))
}

/// The 2.0 `KernelFormat` for the kernel at `path`, from the 1.19 tag the shared sniffer
/// returns (the two enums number their variants differently).
fn payload_format(path: &Path) -> Result<KernelFormat> {
    Ok(match kernel_format(path)? {
        KRUN_KERNEL_FORMAT_ELF => KernelFormat::Elf,
        KRUN_KERNEL_FORMAT_IMAGE_BZ2 => KernelFormat::ImageBz2,
        KRUN_KERNEL_FORMAT_IMAGE_GZ => KernelFormat::ImageGz,
        KRUN_KERNEL_FORMAT_IMAGE_ZSTD => KernelFormat::ImageZstd,
        other => bail!("kernel_format returned unknown tag {other}"),
    })
}

/// Boot `spec` under libkrun 2.0 in this process. Returns only if setup fails; once the
/// guest runs, libkrun ends the process with its exit code.
pub fn boot(spec: &VmSpec) -> Result<()> {
    // Before any thread exists, so every thread libkrun spawns inherits the mask and the
    // signal stays pending for the power-button thread.
    block_sigterm();

    // libkrun logs to stderr (captured to the VMM log). Debug fires on the block and
    // virtio-fs I/O paths and slows a build, so only under VIRTKIT_DEBUG=1.
    let level = if std::env::var("VIRTKIT_DEBUG").as_deref() == Ok("1") {
        LogLevel::Debug
    } else {
        LogLevel::Warn
    };
    krun2::init_log(None, level, LogStyle::Auto, LogOptions::empty()).map_err(krun("logging"))?;

    // libkrun binds and dials these sockets once the VM runs, a vsock port's peer only on
    // the guest's first connect, so they are held until the process ends.
    let mut sockets = Vec::new();
    let mut devices = MmioDeviceManager::new();

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
    devices.add(console.build().map_err(krun("console"))?);

    for (i, disk) in spec.disks.iter().enumerate() {
        devices.add(block_device(i, disk, &mut sockets)?);
    }
    for share in &spec.shares {
        devices.add(fs_device(share)?);
    }
    match &spec.net {
        Net::None => {}
        Net::Tap { tap, mac } => {
            let mac =
                crate::switch::parse_mac(mac).ok_or_else(|| anyhow!("invalid MAC {mac:?}"))?;
            devices.add(NetDevice::new_tap("eth0", tap, &mac, 0).map_err(krun("tap NIC"))?);
        }
    }
    // Switch NICs: one virtio-net device per switch port, dialing the socket the switch
    // listens on and speaking its 4-byte-length framing, with no offloads (the switch
    // terminates TCP and wants complete checksums) and the switch LAN's MTU, so the guest
    // link comes up at it unconfigured. Attach order is interface order (eth0, eth1, …).
    for (i, nic) in spec.nics.iter().enumerate() {
        let socket = SocketPath::new(&nic.socket)
            .with_context(|| format!("switch nic {i}: socket {}", nic.socket.display()))?;
        let mac = crate::switch::parse_mac(&nic.mac)
            .ok_or_else(|| anyhow!("switch nic {i}: invalid MAC {:?}", nic.mac))?;
        let mut net = NetDevice::new_unixstream_path(
            &format!("eth{i}"),
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
    // Unlike 1.19's always-attached device, it is only attached when there are ports; the
    // agent's exec channel always is one.
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
    // virtio-rng, which 1.19 always attached: the guest's /dev/hwrng and early entropy.
    devices.add(RngDevice::new().map_err(krun("rng"))?);
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
        payload_format(&spec.kernel)?,
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
    let vmm = VmmBuilder::new()
        .vcpus(cpus)
        .map_err(krun("vCPUs"))?
        .ram_mib(mem_mib(&spec.mem)?)
        .map_err(krun("memory"))?
        .payload(payload)
        // `vk run --pmu` (trusted guests only) and `--nested`; the host was checked for
        // nesting before this spec was handed over.
        .pmu(spec.pmu)
        .nested_virt(spec.nested)
        .acpi(true)
        .map_err(krun("ACPI"))?
        .shutdown_support(true)
        .add_serial_console(None, Some(log.as_fd()))
        .map_err(krun("serial console"))?
        .devices(devices)
        .build()
        .map_err(krun("building the VM"))?;
    press_power_button_on_sigterm(vmm.handle().map_err(krun("VM handle"))?)?;

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
        match share.cache {
            ShareCache::Auto => FsCachePolicy::Auto,
            ShareCache::Immutable | ShareCache::Ephemeral => FsCachePolicy::Always,
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

fn sigterm_set() -> libc::sigset_t {
    // SAFETY: sigemptyset initializes the set before sigaddset reads it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        set
    }
}

fn block_sigterm() {
    // An inherited SIG_IGN would discard SIGTERM even while blocked, so sigwait never woke.
    // SAFETY: resetting a disposition to its default has no preconditions.
    unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) };
    let set = sigterm_set();
    // SAFETY: a valid set; only the calling thread's mask changes.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
}

/// Handle SIGTERM on a dedicated thread: press the guest's ACPI power button and arm
/// a backstop alarm so the boot child never outlives its parent.
fn press_power_button_on_sigterm(handle: VmmHandle) -> Result<()> {
    std::thread::Builder::new()
        .name("vk-power-button".into())
        .spawn(move || {
            let set = sigterm_set();
            loop {
                let mut sig = 0;
                // SAFETY: a valid set, blocked in every thread; sigwait only reports which.
                if unsafe { libc::sigwait(&set, &mut sig) } != 0 || sig != libc::SIGTERM {
                    continue;
                }
                if let Err(e) = handle.shutdown() {
                    eprintln!("virtkit: pressing the power button: {e}");
                }
                // SAFETY: alarm(2) has no memory-safety preconditions.
                unsafe { libc::alarm(POWER_BUTTON_GRACE_SECS) };
            }
        })
        .context("spawning the power-button thread")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_tags_map_onto_the_2_0_formats() {
        let dir = std::env::temp_dir().join(format!("vk-krun2-fmt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let elf = dir.join("vmlinux");
        std::fs::write(&elf, b"\x7fELF\x02\x01\x01").unwrap();
        assert_eq!(payload_format(&elf).unwrap(), KernelFormat::Elf);
        let gz = dir.join("bzImage");
        std::fs::write(&gz, b"MZ\x00\x00\x1f\x8b\x08").unwrap();
        assert_eq!(payload_format(&gz).unwrap(), KernelFormat::ImageGz);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
