//! libkrun backend: the boot child drives libkrun's C API to boot a [`VmSpec`] in
//! this process. libkrun is the vendored `krun` rlib crate (third_party/libkrun), so
//! it shares virtkit's std — no static-`libkrun.a` double-std to reconcile.
//!
//! libkrun runs as a per-VM subprocess (the [`crate::vmm::Libkrun`] impl re-execs this
//! binary with the spec in `VIRTKIT_BOOT_SPEC`), so it slots into the same lifecycle as the
//! cloud-hypervisor backend — held `Child` / `spawn_tied`, no in-process VMM in
//! the orchestrator. We always supply our own kernel via `krun_set_kernel`, so
//! libkrun never loads libkrunfw (see lib.rs:2848 upstream): the bundled-kernel
//! `.so` is neither linked nor needed.
//!
//! Boots a disk/initramfs guest with our kernel + cmdline-`init=` (PID 1): virtio-blk
//! disks (qcow2 backing chains), built-in virtio-fs shares, per-port vsock, optional
//! tap networking, and the console on the serial-log file. The shutdown eventfd stays
//! unwired (as upstream leaves it on x86_64); teardown is process-kill — see
//! `vm::graceful_vmm_stop`.

use std::ffi::CString;

use anyhow::{Context, Result, bail};

// libkrun's C-ABI entry points, called directly from the linked `krun` crate
// (rlib -> shares virtkit's std; compiler-checked signatures). Every call returns
// >= 0 on success, a negative errno on failure.
use krun::{
    krun_add_disk2, krun_add_net_tap, krun_add_virtiofs4, krun_add_vsock_port2, krun_create_ctx,
    krun_disable_balloon, krun_disable_implicit_init, krun_init_log, krun_set_block_dirty_socket,
    krun_set_console_output, krun_set_kernel, krun_set_nested_virt, krun_set_pmu,
    krun_set_vm_config, krun_start_enter,
};

use crate::vmm::{Disk, Net, VmSpec};

// `krun_set_kernel` kernel-format tags (see the vendored libkrun `KernelFormat`). On x86_64
// libkrun loads a raw ELF `vmlinux` directly (ELF), or scans an "Image" for a compression magic,
// decompresses it, and ELF-loads the result — which is exactly what a distro `bzImage`'s payload
// decompresses to. So a stock gzip/zstd/bzip2 `bzImage` boots via the matching IMAGE_* tag.
const KRUN_KERNEL_FORMAT_ELF: u32 = 1;
const KRUN_KERNEL_FORMAT_IMAGE_BZ2: u32 = 3;
const KRUN_KERNEL_FORMAT_IMAGE_GZ: u32 = 4;
const KRUN_KERNEL_FORMAT_IMAGE_ZSTD: u32 = 5;
const KRUN_DISK_FORMAT_RAW: u32 = 0;
const KRUN_DISK_FORMAT_QCOW2: u32 = 1;

/// Pick the `krun_set_kernel` format tag for `data` (a kernel image). A raw ELF `vmlinux` is
/// `ELF`; anything else is treated as an "Image" whose payload libkrun decompresses then ELF-loads
/// — so we return the tag for the compression whose magic appears EARLIEST, mirroring libkrun's own
/// first-occurrence scan (a stock `bzImage` carries its real payload after the boot setup, and the
/// earliest magic is that payload). Returns `None` for a format libkrun can't load (e.g. xz/lz4, or
/// a raw uncompressed non-ELF), so the caller can point the user at `scripts/extract-vmlinux`.
fn detect_kernel_format(data: &[u8]) -> Option<u32> {
    if data.starts_with(b"\x7fELF") {
        return Some(KRUN_KERNEL_FORMAT_ELF);
    }
    let first = |needle: &[u8]| data.windows(needle.len()).position(|w| w == needle);
    [
        (
            first(&[0x28, 0xb5, 0x2f, 0xfd]),
            KRUN_KERNEL_FORMAT_IMAGE_ZSTD,
        ), // zstd
        (first(&[0x1f, 0x8b, 0x08]), KRUN_KERNEL_FORMAT_IMAGE_GZ), // gzip
        (first(b"BZh"), KRUN_KERNEL_FORMAT_IMAGE_BZ2),             // bzip2
    ]
    .into_iter()
    .filter_map(|(pos, fmt)| pos.map(|p| (p, fmt)))
    .min_by_key(|&(p, _)| p)
    .map(|(_, fmt)| fmt)
}

/// Normalise the guest cmdline's console token. The embedded kernel has virtio_console built
/// in (hvc0) from early boot, so by default CH's `console=ttyS0` is rewritten to `console=hvc0`
/// (the safe, pre-patch behaviour). A BYO/stock distro kernel has virtio_console as a module and
/// only emits early output on the legacy serial, so `keep_serial` (`vk run --console-serial`)
/// leaves `console=ttyS0` in place, served by the COM1 patch in the vendored builder.rs.
fn console_cmdline(cmdline: &str, keep_serial: bool) -> String {
    if keep_serial {
        cmdline.to_string()
    } else {
        cmdline.replace("console=ttyS0", "console=hvc0")
    }
}

/// The `krun_set_kernel` format tag for the kernel at `path`, or a clear error if libkrun cannot
/// load it. Reads the file to sniff its magic (the same bytes libkrun itself scans).
fn kernel_format(path: &std::path::Path) -> Result<u32> {
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

/// Check a libkrun call's return: `>= 0` ok, negative errno on failure.
fn ck(what: &str, rc: i32) -> Result<()> {
    if rc < 0 {
        bail!("{what} failed: rc={rc} (errno {})", -rc);
    }
    Ok(())
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("nul byte in libkrun argument")
}

/// Parse a memory size token into MiB for `krun_set_vm_config`, accepting the same
/// forms as the CLI and cloud-hypervisor (`<n>G`, `<n>M`, plain MiB — see
/// `run::parse_mem_mib`).
fn mem_mib(mem: &str) -> Result<u32> {
    crate::run::parse_mem_mib(mem)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| anyhow::anyhow!("memory size {mem:?} is not <n>G, <n>M or a MiB count"))
}

/// Boot `spec` under libkrun in this process. Returns only when the guest powers
/// off (or never, until then) — the caller is the libkrun boot subprocess.
pub fn boot(spec: &VmSpec) -> Result<()> {
    unsafe {
        // libkrun logs to stderr (captured to the VMM log). Its debug level fires on the
        // block / virtio-fs I/O hot path and measurably slows a build, so default to warn
        // and only raise to debug under VIRTKIT_DEBUG=1. (2 = warn, 4 = debug.)
        let level = if std::env::var("VIRTKIT_DEBUG").as_deref() == Ok("1") {
            4
        } else {
            2
        };
        krun_init_log(2, level, 0, 0);

        let ctx = krun_create_ctx();
        ck("krun_create_ctx", ctx)?;
        let ctx = ctx as u32;

        // libkrun's API takes a u8 vCPU count; refuse rather than silently wrap
        // (e.g. `--cpus host` on a 256-core machine would truncate to 0).
        let cpus: u8 = spec.cpus.try_into().map_err(|_| {
            anyhow::anyhow!("libkrun supports at most 255 vCPUs (got {})", spec.cpus)
        })?;
        ck(
            "krun_set_vm_config",
            krun_set_vm_config(ctx, cpus, mem_mib(&spec.mem)?),
        )?;

        // Guest PMU (`vk run --pmu`, trusted guests only): the vendored patch keeps
        // CPUID leaf 0xA as KVM reports it, so KVM's vPMU backs in-guest hardware
        // counters. Off by default — see VmSpec::pmu.
        if spec.pmu {
            ck("krun_set_pmu", krun_set_pmu(ctx, true))?;
        }

        // Nested virt (`vk run --nested`): libkrun masks the host's VMX/SVM CPUID bit
        // unless asked, and without it the guest's kvm_intel/kvm_amd never registers
        // /dev/kvm. The host is already known to allow nesting — `run::spawn_vmm`
        // refused this spec otherwise, on either backend.
        if spec.nested {
            ck("krun_set_nested_virt", krun_set_nested_virt(ctx, true))?;
        }

        // virtio-balloon, the same axis CH spells `--balloon …,free_page_reporting=on`:
        // libkrun attaches one by default, so only the opt-out needs a call (the
        // vendored krun_disable_balloon patch).
        if !spec.balloon {
            ck("krun_disable_balloon", krun_disable_balloon(ctx))?;
        }

        // Guest console -> the serial-log file, matching CH's `--serial file=`; the
        // orchestrator reads that file for diagnostics. libkrun routes both its
        // implicit virtio-console (hvc0) and (with the virtkit early-console patch in
        // builder.rs) the legacy 16550 COM1 (ttyS0) to this file.
        //
        // Console plan:
        //   - Embedded kernel (default): virtio_console is built in, so hvc0 works from
        //     early boot -> rewrite console=ttyS0 -> console=hvc0 (the safe default;
        //     preserves the pre-patch behaviour).
        //   - BYO/stock distro kernel (e.g. modular Debian): virtio_console is a module,
        //     so early output only appears on the legacy serial -> `vk run --console-serial`
        //     (spec.console_serial) keeps console=ttyS0 (served by the COM1 patch).
        let serial_log = cstr(&spec.serial_log.to_string_lossy());
        ck(
            "krun_set_console_output",
            krun_set_console_output(ctx, serial_log.as_ptr()),
        )?;

        // our own kernel + cmdline; PID 1 is chosen by `init=` on the cmdline. The format is
        // sniffed from the image so a custom (e.g. stock distro) kernel boots, not just our ELF.
        let kformat = kernel_format(&spec.kernel)?;
        let kernel = cstr(&spec.kernel.to_string_lossy());
        // An image kernel (VIRTKIT_KERNEL=image) is a stock, modular kernel whose
        // virtio_console (hvc0) is not loaded in the preinit, so it must keep the
        // always-present legacy COM1 (ttyS0, served by the early-console patch) — else
        // the guest console is dead early and the agent stalls before the serve is up.
        // The pinned kernel has hvc0, so kernel==default keeps the hvc0 rewrite.
        let keep_serial = spec.console_serial
            || spec
                .cmdline
                .split_whitespace()
                .any(|t| t == "VIRTKIT_KERNEL=image");
        let cmdline_str = console_cmdline(&spec.cmdline, keep_serial);
        let cmdline = cstr(&cmdline_str);
        let initramfs = spec.initramfs.as_ref().map(|p| cstr(&p.to_string_lossy()));
        ck(
            "krun_set_kernel",
            krun_set_kernel(
                ctx,
                kernel.as_ptr(),
                kformat,
                initramfs.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                cmdline.as_ptr(),
            ),
        )?;

        // virtio-blk disks in order (first = /dev/vda). qcow2 overlays resolve their
        // backing chain (KRUN_DISK_FORMAT_QCOW2); raw bases use KRUN_DISK_FORMAT_RAW.
        for (i, disk) in spec.disks.iter().enumerate() {
            add_disk(ctx, i, disk)?;
        }

        // virtio-fs shares. libkrun has no external vhost-user-fs, so it mounts the host
        // directory directly with its built-in virtio-fs; no separate virtiofsd runs
        // (the boot sites skip it when libkrun is selected). shm_size 0 = no DAX window.
        for share in &spec.shares {
            let tag = cstr(&share.tag);
            let dir = cstr(&share.host_dir.to_string_lossy());
            // The id-map rules for this share, joined by ',' as krun_add_virtiofs4 expects;
            // an empty map yields an empty string, which the FFI treats as an identity map.
            let uid_map = cstr(&share.uid_map.join(","));
            let gid_map = cstr(&share.gid_map.join(","));
            ck(
                "krun_add_virtiofs4",
                krun_add_virtiofs4(
                    ctx,
                    tag.as_ptr(),
                    dir.as_ptr(),
                    0,
                    share.read_only,
                    uid_map.as_ptr(),
                    gid_map.as_ptr(),
                ),
            )?;
        }

        // Networking. Net::Tap attaches a host tap by name (like CH's `--net tap=,mac=`);
        // the guest gets a static address from the cmdline. Net::None is switch-mode: the
        // guest agent bridges eth0 over the vsock net port, so no VMM net device is added.
        match &spec.net {
            Net::None => {}
            Net::Tap { tap, mac } => {
                let tap_c = cstr(tap);
                let mac = crate::switch::parse_mac(mac)
                    .ok_or_else(|| anyhow::anyhow!("invalid MAC {mac:?}"))?;
                ck(
                    "krun_add_net_tap",
                    krun_add_net_tap(ctx, tap_c.as_ptr(), mac.as_ptr(), 0, 0),
                )?;
            }
        }

        // vsock ports, each on its own `<base>_<port>` host socket. listen=true:
        // libkrun listens there and forwards host connections to the guest port
        // (the exec channel; `vsock-auto://` clients dial it directly — nothing
        // listens on the base path itself under libkrun). listen=false: the guest
        // dials the port and libkrun forwards to the host socket, where the host
        // already listens (the switch and ssh-agent bridges). cloud-hypervisor
        // gets the equivalent wiring from its single hybrid socket.
        for vp in &spec.vsock_ports {
            let path = cstr(&vp.socket.to_string_lossy());
            ck(
                "krun_add_vsock_port2",
                krun_add_vsock_port2(ctx, vp.port, path.as_ptr(), vp.listen),
            )?;
        }

        // our cmdline's init= is PID 1; don't let libkrun inject /init.krun.
        ck(
            "krun_disable_implicit_init",
            krun_disable_implicit_init(ctx),
        )?;

        // blocks until the guest powers off.
        ck("krun_start_enter", krun_start_enter(ctx))?;
    }
    Ok(())
}

unsafe fn add_disk(ctx: u32, index: usize, disk: &Disk) -> Result<()> {
    let block_id = cstr(&format!("vd{}", (b'a' + index as u8) as char));
    let path = cstr(&disk.path.to_string_lossy());
    let format = if disk.qcow2 {
        KRUN_DISK_FORMAT_QCOW2
    } else {
        KRUN_DISK_FORMAT_RAW
    };
    ck("krun_add_disk2", unsafe {
        krun_add_disk2(ctx, block_id.as_ptr(), path.as_ptr(), format, disk.readonly)
    })?;
    // Dirty-block tracking (build stages): serve the drain protocol on the given socket so a
    // checkpoint captures only the delta. Set only on the writable stage overlay.
    if let Some(sock) = &disk.dirty_control_socket {
        let sock = cstr(&sock.to_string_lossy());
        ck("krun_set_block_dirty_socket", unsafe {
            krun_set_block_dirty_socket(ctx, block_id.as_ptr(), sock.as_ptr())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        KRUN_KERNEL_FORMAT_ELF, KRUN_KERNEL_FORMAT_IMAGE_BZ2, KRUN_KERNEL_FORMAT_IMAGE_GZ,
        KRUN_KERNEL_FORMAT_IMAGE_ZSTD, console_cmdline, detect_kernel_format, mem_mib,
    };

    #[test]
    fn kernel_format_detection() {
        // A raw ELF vmlinux (our embedded kernel) → ELF.
        assert_eq!(
            detect_kernel_format(b"\x7fELF\x02\x01\x01"),
            Some(KRUN_KERNEL_FORMAT_ELF)
        );
        // A bzImage: an `MZ` PE header + boot setup, then the real compressed payload. The
        // earliest compression magic is the payload; pick its format (matching libkrun's scan).
        let mut zst = b"MZ".to_vec();
        zst.extend(std::iter::repeat_n(0u8, 4096)); // stand-in for the boot setup
        zst.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // zstd payload
        assert_eq!(
            detect_kernel_format(&zst),
            Some(KRUN_KERNEL_FORMAT_IMAGE_ZSTD)
        );
        let mut gz = b"MZ\x00\x00".to_vec();
        gz.extend_from_slice(&[0x1f, 0x8b, 0x08]);
        assert_eq!(detect_kernel_format(&gz), Some(KRUN_KERNEL_FORMAT_IMAGE_GZ));
        assert_eq!(
            detect_kernel_format(b"MZ....BZh9"),
            Some(KRUN_KERNEL_FORMAT_IMAGE_BZ2)
        );
        // Earliest magic wins: a real zstd payload before a spurious later gzip byte-sequence.
        let mut mixed = vec![0u8; 200];
        mixed.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]); // zstd first
        mixed.extend_from_slice(&[0x1f, 0x8b, 0x08]); // spurious gzip later
        assert_eq!(
            detect_kernel_format(&mixed),
            Some(KRUN_KERNEL_FORMAT_IMAGE_ZSTD)
        );
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
