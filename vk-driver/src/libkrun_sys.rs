//! libkrun backend: the `__libkrun-boot` subcommand drives libkrun's C API to
//! boot a [`VmSpec`] in this process. libkrun is the vendored `krun` rlib crate
//! (third_party/libkrun), so it shares virtkit's std — no static-`libkrun.a`
//! double-std to reconcile.
//!
//! libkrun runs as a per-VM subprocess (the [`crate::vmm::Libkrun`] impl execs
//! `vk __libkrun-boot <spec-json>`), so it slots into the same lifecycle as the
//! cloud-hypervisor backend — held `Child` / `spawn_tied`, no in-process VMM in
//! the orchestrator. We always supply our own kernel via `krun_set_kernel`, so
//! libkrun never loads libkrunfw (see lib.rs:2848 upstream): the bundled-kernel
//! `.so` is neither linked nor needed.
//!
//! Boots a disk/initramfs guest with our kernel + cmdline-`init=` (PID 1): virtio-blk
//! disks (qcow2 backing chains), built-in virtio-fs shares, per-port vsock, optional
//! tap networking, and the console on the serial-log file. The shutdown eventfd stays
//! unwired (as upstream leaves it on x86_64); teardown is process-kill — see
//! `vm::stop_vm`.

use std::ffi::CString;

use anyhow::{Result, bail};

// libkrun's C-ABI entry points, called directly from the linked `krun` crate
// (rlib -> shares virtkit's std; compiler-checked signatures). Every call returns
// >= 0 on success, a negative errno on failure.
use krun::{
    krun_add_disk2, krun_add_net_tap, krun_add_virtiofs3, krun_add_vsock_port2, krun_create_ctx,
    krun_disable_implicit_init, krun_init_log, krun_set_console_output, krun_set_kernel,
    krun_set_vm_config, krun_start_enter,
};

use crate::vmm::{Disk, Net, VmSpec};

const KRUN_KERNEL_FORMAT_ELF: u32 = 1;
const KRUN_DISK_FORMAT_RAW: u32 = 0;
const KRUN_DISK_FORMAT_QCOW2: u32 = 1;

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

/// Parse a `aa:bb:cc:dd:ee:ff` MAC into the 6 bytes `krun_add_net_tap` expects.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut octets = s.split(':');
    for byte in &mut mac {
        let octet = octets
            .next()
            .ok_or_else(|| anyhow::anyhow!("MAC {s:?} has fewer than six octets"))?;
        *byte = u8::from_str_radix(octet, 16)
            .map_err(|_| anyhow::anyhow!("invalid MAC octet {octet:?} in {s:?}"))?;
    }
    if octets.next().is_some() {
        bail!("MAC {s:?} has more than six octets");
    }
    Ok(mac)
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
/// off (or never, until then) — the caller is the `__libkrun-boot` subprocess.
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

        // Guest console -> the serial-log file, matching CH's `--serial file=`; the
        // orchestrator reads that file for diagnostics. libkrun routes its implicit
        // console (a virtio-console, hvc0) here, so we leave the implicit console on
        // and normalise the cmdline's console token from CH's ttyS0 to hvc0 below.
        let serial_log = cstr(&spec.serial_log.to_string_lossy());
        ck(
            "krun_set_console_output",
            krun_set_console_output(ctx, serial_log.as_ptr()),
        )?;

        // our own kernel + cmdline; PID 1 is chosen by `init=` on the cmdline.
        let kernel = cstr(&spec.kernel.to_string_lossy());
        let cmdline = cstr(&spec.cmdline.replace("console=ttyS0", "console=hvc0"));
        let initramfs = spec.initramfs.as_ref().map(|p| cstr(&p.to_string_lossy()));
        ck(
            "krun_set_kernel",
            krun_set_kernel(
                ctx,
                kernel.as_ptr(),
                KRUN_KERNEL_FORMAT_ELF,
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
            ck(
                "krun_add_virtiofs3",
                krun_add_virtiofs3(ctx, tag.as_ptr(), dir.as_ptr(), 0, share.read_only),
            )?;
        }

        // Networking. Net::Tap attaches a host tap by name (like CH's `--net tap=,mac=`);
        // the guest gets a static address from the cmdline. Net::None is switch-mode: the
        // guest agent bridges eth0 over the vsock net port, so no VMM net device is added.
        match &spec.net {
            Net::None => {}
            Net::Tap { tap, mac } => {
                let tap_c = cstr(tap);
                let mac = parse_mac(mac)?;
                ck(
                    "krun_add_net_tap",
                    krun_add_net_tap(ctx, tap_c.as_ptr(), mac.as_ptr(), 0, 0),
                )?;
            }
        }

        // vsock ports. listen=true: libkrun listens on the host unix socket and
        // forwards host connections to the guest port (the exec channel). listen=false:
        // the guest dials the port and libkrun forwards to the host socket, where the
        // host already listens (the switch and ssh-agent bridges). cloud-hypervisor
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
    })
}

#[cfg(test)]
mod tests {
    use super::{mem_mib, parse_mac};

    #[test]
    fn mac_roundtrip() {
        assert_eq!(
            parse_mac("52:54:00:d2:f0:01").unwrap(),
            [0x52, 0x54, 0x00, 0xd2, 0xf0, 0x01]
        );
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn mac_rejects_malformed() {
        assert!(parse_mac("52:54:00:d2:f0").is_err()); // too few
        assert!(parse_mac("52:54:00:d2:f0:01:02").is_err()); // too many
        assert!(parse_mac("52:54:00:zz:f0:01").is_err()); // non-hex
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
