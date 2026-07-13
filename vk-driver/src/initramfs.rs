//! Transcode a rootfs tar into a cpio initramfs (cpio.rs), injecting the static
//! agent as PID 1 — the RAM-boot counterpart of ext4.rs. The rootfs tar
//! comes from a `source::Source` (docker export or an OCI pull). No kernel
//! modules are injected: generic guests boot the pinned guest kernel, which has
//! virtio (blk/net/vsock) + ext4 built in.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

use crate::cpio::CpioWriter;

/// Where the injected agent lands in the rootfs (relative path).
pub const CMDRUNNER_PATH: &str = "usr/local/bin/vk-agent";

/// Build a *minimal* cpio initramfs at `out` containing only the agent as `/init`.
/// Used by the disk-boot path (e.g. build): the kernel runs this agent as PID 1
/// from RAM, which then mounts the real image ext4 and `pivot_root`s into it (see
/// `init::run_init`). This keeps the agent out of every built image — it is supplied
/// by the boot medium, never written into the rootfs. The kernel auto-mounts devtmpfs,
/// so no `/dev/console` node is needed in the archive.
pub fn build_agent_initramfs(agent: &Path, out: &Path) -> Result<()> {
    build_agent_initramfs_with_config(agent, None, out)
}

/// [`build_agent_initramfs`] plus an optional boot-time service config: the JSON
/// rides the archive at [`vk_core::runcfg::INITRAMFS_PATH`], where the agent reads
/// it before pivoting. This is how a service's runtime config reaches a byte-clean
/// image — rendered per boot (the cpio is rebuilt per boot anyway), never baked in.
pub fn build_agent_initramfs_with_config(
    agent: &Path,
    config: Option<&vk_core::runcfg::RunConfig>,
    out: &Path,
) -> Result<()> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut cpio = CpioWriter::new(std::io::BufWriter::new(file));
    let f = std::fs::File::open(agent).with_context(|| format!("opening {}", agent.display()))?;
    let size = f.metadata()?.len();
    cpio.file("init", 0o755, size as u32, f)?;
    if let Some(cfg) = config {
        cpio.file_bytes(
            vk_core::runcfg::INITRAMFS_PATH,
            0o600,
            cfg.to_json().as_bytes(),
        )?;
    }
    cpio.finish()?;
    Ok(())
}

/// Build the preinit initramfs for a non-default-axis boot: the agent as `/init`,
/// the image's boot-critical kernel modules under `lib/modules/<ver>/…`, an ordered
/// load list at `virtkit-modules` (the absolute in-initramfs `.ko` paths, one per
/// line), and — when given — the boot config at [`vk_core::runcfg::INITRAMFS_PATH`].
/// The agent preinit reads `/virtkit-modules`, `insmod`s each entry in order, then
/// pivots into the real root and (for image init) hands off to the image's own init.
/// `modules` is a list of (relative path under `lib/modules/<ver>`, bytes) in load
/// order, and `load_order_abs` the matching absolute paths as they land in the
/// archive. Both are empty when the boot runs on the pinned kernel (virtio + ext4
/// built in), leaving just the agent and an empty load list.
pub fn build_fullvm_initramfs(
    agent: &Path,
    modules: &[(String, Vec<u8>)],
    ver: &str,
    load_order_abs: &[String],
    config: Option<&vk_core::runcfg::RunConfig>,
    out: &Path,
) -> Result<()> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut cpio = CpioWriter::new(std::io::BufWriter::new(file));

    // The agent as PID 1: it execs via /proc/self/exe, so `/init` alone suffices.
    let f = std::fs::File::open(agent).with_context(|| format!("opening {}", agent.display()))?;
    let size = f.metadata()?.len();
    cpio.file("init", 0o755, size as u32, f)?;

    for (rel, bytes) in modules {
        let guest = format!("lib/modules/{ver}/{rel}");
        cpio.dirs_for(&guest, 0o755)?;
        cpio.file_bytes(&guest, 0o644, bytes)?;
    }

    cpio.file_bytes(
        "virtkit-modules",
        0o644,
        load_order_abs.join("\n").as_bytes(),
    )?;

    if let Some(cfg) = config {
        cpio.file_bytes(
            vk_core::runcfg::INITRAMFS_PATH,
            0o600,
            cfg.to_json().as_bytes(),
        )?;
    }
    cpio.finish()?;
    Ok(())
}

/// Build a cpio initramfs at `out` from the rootfs tar streamed by `tar` (a single
/// pass — no tar file needed), injecting each host file in `injects` at its guest
/// path with the given mode (the agent PID 1, plus e.g. the captured
/// `/etc/virtkit/{env,user}`). Hardlinks/device nodes/fifos are skipped — a generic
/// rootfs (alpine, distroless) has none that matter for booting.
pub fn build_initramfs_injecting(
    tar: impl Read,
    injects: &[(&str, &Path, u16)],
    out: &Path,
) -> Result<()> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut cpio = CpioWriter::new(std::io::BufWriter::new(file));

    let mut ar = tar::Archive::new(tar);
    for entry in ar.entries()? {
        let mut e = entry?;
        let header = e.header();
        let mode = header.mode().unwrap_or(0o644) & 0o7777;
        let etype = header.entry_type();
        let path = e.path()?.to_string_lossy().into_owned();
        let name = path
            .trim_start_matches("./")
            .trim_start_matches('/')
            .trim_end_matches('/');
        if name.is_empty() {
            continue;
        }
        if etype.is_dir() {
            cpio.dir(name, mode)?;
        } else if etype.is_symlink() {
            if let Some(target) = e.link_name()? {
                cpio.symlink(name, &target.to_string_lossy())?;
            }
        } else if etype.is_file() {
            let size = header.size()?;
            cpio.file(name, mode, size as u32, &mut e)?;
        }
    }

    for (guest, host, mode) in injects {
        cpio.dirs_for(guest, 0o755)?;
        let f = std::fs::File::open(host)
            .with_context(|| format!("opening inject {}", host.display()))?;
        let size = f.metadata()?.len();
        cpio.file(guest, u32::from(*mode), size as u32, f)?;
    }
    cpio.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_initramfs_carries_the_boot_config() {
        let tmp = std::env::temp_dir().join(format!("vk-initramfs-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let agent = tmp.join("agent");
        std::fs::write(&agent, b"#!agent").unwrap();

        let cfg = vk_core::runcfg::RunConfig {
            entrypoint: vec!["redis-server".into()],
            ..Default::default()
        };
        let with = tmp.join("with.cpio");
        build_agent_initramfs_with_config(&agent, Some(&cfg), &with).unwrap();
        let bytes = std::fs::read(&with).unwrap();
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(has(vk_core::runcfg::INITRAMFS_PATH.as_bytes()));
        assert!(has(b"redis-server"));

        // without a config the entry is absent (plain run/build boots stay as-is).
        let without = tmp.join("without.cpio");
        build_agent_initramfs(&agent, &without).unwrap();
        let bytes = std::fs::read(&without).unwrap();
        assert!(
            !bytes
                .windows(vk_core::runcfg::INITRAMFS_PATH.len())
                .any(|w| w == vk_core::runcfg::INITRAMFS_PATH.as_bytes())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fullvm_initramfs_carries_modules_and_load_list() {
        let tmp = std::env::temp_dir().join(format!("vk-fullvm-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let agent = tmp.join("agent");
        std::fs::write(&agent, b"#!agent").unwrap();

        let ver = "6.1.0-99-amd64";
        let modules = vec![
            (
                "kernel/drivers/virtio/virtio.ko".to_string(),
                b"ELF-virtio".to_vec(),
            ),
            ("kernel/fs/ext4/ext4.ko".to_string(), b"ELF-ext4".to_vec()),
        ];
        let load_order = vec![
            format!("/lib/modules/{ver}/kernel/drivers/virtio/virtio.ko"),
            format!("/lib/modules/{ver}/kernel/fs/ext4/ext4.ko"),
        ];
        let out = tmp.join("preinit.cpio");
        build_fullvm_initramfs(&agent, &modules, ver, &load_order, None, &out).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        // the load list is present and names an absolute module path
        assert!(has(b"virtkit-modules"));
        assert!(has(load_order[0].as_bytes()));
        // a module lands at its in-initramfs path (relative, no leading slash)
        assert!(has(
            format!("lib/modules/{ver}/kernel/fs/ext4/ext4.ko").as_bytes()
        ));
        // and the agent is present as /init
        assert!(has(b"init"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fullvm_initramfs_pinned_kernel_has_agent_and_empty_load_list() {
        // The pinned-kernel path (--kernel default / a path): no extraction, no
        // modules — the initramfs still carries the agent as /init and an (empty)
        // load list.
        let tmp = std::env::temp_dir().join(format!("vk-fullvm-pinned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let agent = tmp.join("agent");
        std::fs::write(&agent, b"#!agent").unwrap();

        let out = tmp.join("preinit.cpio");
        build_fullvm_initramfs(&agent, &[], "6.1.0-99-amd64", &[], None, &out).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"init"));
        assert!(has(b"virtkit-modules"));
        // no module lands under lib/modules
        assert!(!has(b"lib/modules"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
