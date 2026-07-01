//! Transcode a rootfs tar into a cpio initramfs (cpio.rs), injecting the static
//! agent as PID 1 — the RAM-boot counterpart of ext4.rs. The rootfs tar
//! comes from a `source::Source` (docker export or an OCI pull). No kernel
//! modules are injected: generic guests boot the pinned guest kernel, which has
//! virtio (blk/net/vsock) + ext4 built in.

use std::path::Path;

use anyhow::{Context, Result};

use crate::cpio::CpioWriter;

/// Where the injected agent lands in the rootfs (relative path).
pub const CMDRUNNER_PATH: &str = "usr/local/bin/vk-agent";

/// Build a cpio initramfs at `out` from the rootfs `tar_path`, injecting the
/// static agent as PID 1. Convenience wrapper over [`build_initramfs_injecting`].
pub fn build_initramfs(tar_path: &Path, agent: &Path, out: &Path) -> Result<()> {
    build_initramfs_injecting(tar_path, &[(CMDRUNNER_PATH, agent, 0o755)], out)
}

/// Build a *minimal* cpio initramfs at `out` containing only the agent as `/init`.
/// Used by the disk-boot path (e.g. build): the kernel runs this agent as PID 1
/// from RAM, which then mounts the real image ext4 and `pivot_root`s into it (see
/// `init::run_init`). This keeps the agent out of every built image — it is supplied
/// by the boot medium, never written into the rootfs. The kernel auto-mounts devtmpfs,
/// so no `/dev/console` node is needed in the archive.
pub fn build_agent_initramfs(agent: &Path, out: &Path) -> Result<()> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut cpio = CpioWriter::new(std::io::BufWriter::new(file));
    let f = std::fs::File::open(agent).with_context(|| format!("opening {}", agent.display()))?;
    let size = f.metadata()?.len();
    cpio.file("init", 0o755, size as u32, f)?;
    cpio.finish()?;
    Ok(())
}

/// Build a cpio initramfs at `out` from the rootfs `tar_path`, injecting each host
/// file in `injects` at its guest path with the given mode (the agent PID 1, plus
/// e.g. the captured `/etc/virtkit/{env,user}`). Hardlinks/device nodes/fifos are
/// skipped — a generic rootfs (alpine, distroless) has none that matter for booting.
pub fn build_initramfs_injecting(
    tar_path: &Path,
    injects: &[(&str, &Path, u16)],
    out: &Path,
) -> Result<()> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut cpio = CpioWriter::new(std::io::BufWriter::new(file));

    let src =
        std::fs::File::open(tar_path).with_context(|| format!("opening {}", tar_path.display()))?;
    let mut ar = tar::Archive::new(src);
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
