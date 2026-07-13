//! The preinit initramfs boot used whenever a `vk run` axis leaves the default:
//! `--kernel image` (boot the image's OWN modular kernel) and/or `--init image`
//! (hand PID 1 to the image's OWN init/systemd). This module reads the image's ext4
//! host-side (no mount, via [`crate::ext4_read::Ext4Reader`]) and, for the image
//! kernel, extracts the two pieces libkrun needs: the raw kernel `vmlinuz` and the
//! boot-critical kernel modules. It then assembles the preinit initramfs the agent
//! boots from — the agent as `/init` plus any `.ko` files and an ordered load list —
//! so the preinit can `insmod` virtio/ext4 before mounting the real root and (for
//! image init) exec'ing the image's `/sbin/init`. With `--kernel default` the pinned
//! kernel has virtio/ext4 built in, so no extraction and no modules are needed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::ext4_read::{Ext4Reader, FileType};
use crate::run::KernelSource;

/// Boot-critical modules, in load order. A stock Debian bookworm kernel is
/// modular, so the preinit must `insmod` these before mounting `/dev/vda`:
/// virtio-pci + virtio-blk + ext4 (and their dependencies) reach the rootfs; the
/// last three give the reparented `vk-agent serve` its AF_VSOCK transport. Any
/// name absent from the image (e.g. `virtio_ring`, often built into `virtio.ko`)
/// is skipped with a warning.
const WANTED_MODULES: &[&str] = &[
    "virtio",
    "virtio_ring",
    "virtio_pci_legacy_dev",
    "virtio_pci_modern_dev",
    "virtio_pci",
    "virtio_blk",
    "crc16",
    "crc32c_generic",
    "libcrc32c",
    "mbcache",
    "jbd2",
    "ext4",
    // fuse + virtiofs so the preinit can mount --volume/--workdir host shares.
    "fuse",
    "virtiofs",
    // tun so the preinit can create the eth0 tap bridged to the vk switch (--net).
    "tun",
    "vsock",
    "vmw_vsock_virtio_transport_common",
    "vmw_vsock_virtio_transport",
];

/// The kernel + preinit initramfs a preinit boot runs on.
pub struct FullVmBoot {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
}

/// Read the image ext4 and build the preinit initramfs (agent as `/init`, any `.ko`
/// files under `/lib/modules/<ver>`, an ordered load list at `/virtkit-modules`, and
/// the optional boot config). `kernel_out` and `initramfs_out` are scratch paths to
/// write; `agent` is the vk-agent binary path.
///
/// The kernel depends on `kernel_source`: with [`KernelSource::Image`] the image's
/// own kernel is extracted to `kernel_out` and its boot-critical modules ride the
/// initramfs; with [`KernelSource::Default`] or [`KernelSource::Path`] the boot runs
/// on `pinned_kernel` (the caller's resolved pinned/explicit kernel, virtio + ext4
/// built in) and no modules are gathered.
pub fn prepare(
    ext4: &Path,
    agent: &Path,
    kernel_out: &Path,
    initramfs_out: &Path,
    boot_cfg: Option<&vk_core::runcfg::RunConfig>,
    kernel_source: &KernelSource,
    pinned_kernel: &Path,
) -> Result<FullVmBoot> {
    let reader =
        Ext4Reader::open(ext4).with_context(|| format!("opening image ext4 {}", ext4.display()))?;
    let ver = kernel_version(&reader)?;

    let mut modules: Vec<(String, Vec<u8>)> = Vec::new();
    let mut load_order_abs: Vec<String> = Vec::new();
    let kernel = if *kernel_source == KernelSource::Image {
        // The image's kernel, reduced to a bare ELF vmlinux — libkrun's most reliable
        // load path. A distro `vmlinuz` is a bzImage whose payload is a compressed
        // vmlinux; Debian's is xz, which libkrun's own bzImage sniffing does not cover,
        // so we do the `scripts/extract-vmlinux` scan here (find the compression magic,
        // decompress, verify ELF).
        let raw = read_kernel(&reader, &ver)?;
        let kernel_bytes =
            extract_vmlinux(&raw).context("extracting the ELF vmlinux from the image's kernel")?;
        std::fs::write(kernel_out, &kernel_bytes)
            .with_context(|| format!("writing extracted kernel to {}", kernel_out.display()))?;

        // Resolve the boot-critical module basenames to their in-image relative paths
        // (under /lib/modules/<ver>) via modules.dep, then read each .ko out.
        let dep_path = format!("/lib/modules/{ver}/modules.dep");
        let dep_text = String::from_utf8(
            reader
                .read_file(&dep_path)
                .with_context(|| format!("reading {dep_path}"))?,
        )
        .with_context(|| format!("{dep_path} is not UTF-8"))?;
        let rel_paths = resolve_module_paths(&dep_text, WANTED_MODULES);

        for rel in &rel_paths {
            if rel.ends_with(".ko.xz") || rel.ends_with(".ko.zst") || rel.ends_with(".ko.gz") {
                bail!("compressed modules unsupported: {rel} (bookworm ships uncompressed .ko)");
            }
            let abs_in_image = format!("/lib/modules/{ver}/{rel}");
            match reader.read_file(&abs_in_image) {
                Ok(bytes) => {
                    load_order_abs.push(format!("/lib/modules/{ver}/{rel}"));
                    modules.push((rel.clone(), bytes));
                }
                Err(e) => eprintln!("virtkit: skipping module {abs_in_image} (unreadable: {e:#})"),
            }
        }
        kernel_out.to_path_buf()
    } else {
        // The pinned/explicit kernel has virtio + ext4 built in: no extraction, no
        // module initramfs. The agent still rides the initramfs as /init for the pivot
        // and (with --init image) the handoff.
        pinned_kernel.to_path_buf()
    };

    crate::initramfs::build_fullvm_initramfs(
        agent,
        &modules,
        &ver,
        &load_order_abs,
        boot_cfg,
        initramfs_out,
    )?;

    Ok(FullVmBoot {
        kernel,
        initramfs: initramfs_out.to_path_buf(),
    })
}

/// The single kernel version directory under `/lib/modules`. Errors if there is
/// not exactly one (a stock image ships one; zero or several is ambiguous).
fn kernel_version(reader: &Ext4Reader) -> Result<String> {
    let dirs: Vec<String> = reader
        .list_dir("/lib/modules")
        .context("listing /lib/modules")?
        .into_iter()
        .filter(|(_, ft)| *ft == FileType::Dir)
        .map(|(name, _)| name)
        .collect();
    match dirs.len() {
        1 => Ok(dirs.into_iter().next().unwrap()),
        0 => bail!("/lib/modules has no kernel version directory"),
        n => bail!("/lib/modules has {n} version directories, expected exactly one: {dirs:?}"),
    }
}

/// The image's raw kernel image bytes: `/boot/vmlinuz-<ver>`, falling back to the
/// sole `vmlinuz-*` regular file under `/boot`.
fn read_kernel(reader: &Ext4Reader, ver: &str) -> Result<Vec<u8>> {
    let exact = format!("/boot/vmlinuz-{ver}");
    if let Ok(bytes) = reader.read_file(&exact) {
        return Ok(bytes);
    }
    let candidates: Vec<String> = reader
        .list_dir("/boot")
        .context("listing /boot")?
        .into_iter()
        .filter(|(name, ft)| *ft == FileType::Regular && name.starts_with("vmlinuz-"))
        .map(|(name, _)| name)
        .collect();
    match candidates.len() {
        1 => {
            let path = format!("/boot/{}", candidates[0]);
            reader
                .read_file(&path)
                .with_context(|| format!("reading kernel {path}"))
        }
        0 => bail!("no {exact} and no vmlinuz-* under /boot"),
        _ => bail!("{exact} not found and multiple vmlinuz-* under /boot: {candidates:?}"),
    }
}

/// ELF magic (`\x7fELF`).
const ELF_MAGIC: &[u8] = &[0x7f, 0x45, 0x4c, 0x46];

/// Reduce a distro kernel image to a bare ELF `vmlinux`. If `image` is already ELF
/// it is returned as-is; otherwise it is a bzImage whose payload is a compressed
/// vmlinux — scan for a known compression magic and decompress from there with the
/// matching decompressor, accepting the first result that is an ELF. This mirrors
/// the kernel tree's `scripts/extract-vmlinux`, including shelling out to the codec
/// CLIs: a kernel's xz payload uses the x86 BCJ filter, which the host `xz` handles
/// but pure-Rust decoders do not, so a codec binary on PATH is required.
fn extract_vmlinux(image: &[u8]) -> Result<Vec<u8>> {
    if image.starts_with(ELF_MAGIC) {
        return Ok(image.to_vec());
    }
    // (magic, argv) in the order extract-vmlinux probes them. Each command reads the
    // compressed tail on stdin and writes the plain vmlinux on stdout; a trailing
    // byte tail after the stream is expected, so single-stream/lenient modes are used.
    const CODECS: &[(&[u8], &[&str])] = &[
        (&[0x1f, 0x8b, 0x08], &["gzip", "-dc"]),
        (
            &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
            &["xz", "-dc", "--single-stream"],
        ),
        (&[0x28, 0xb5, 0x2f, 0xfd], &["zstd", "-q", "-d", "-c"]),
        (&[0x02, 0x21, 0x4c, 0x18], &["lz4", "-d", "-c"]),
        (&[0x42, 0x5a, 0x68], &["bzip2", "-dc"]),
    ];
    let mut tried_any = false;
    for (magic, argv) in CODECS {
        let mut from = 0;
        while let Some(off) = find_subslice(&image[from..], magic) {
            let at = from + off;
            match pipe_through(argv, &image[at..]) {
                Ok(out) if out.starts_with(ELF_MAGIC) => return Ok(out),
                Ok(_) => {}
                Err(PipeError::Spawn) => break, // codec not installed: skip this magic
                Err(PipeError::Run) => tried_any = true,
            }
            from = at + 1;
        }
    }
    if tried_any {
        bail!(
            "found a compressed payload in the kernel image but no decompressor \
             produced an ELF vmlinux"
        );
    }
    bail!(
        "could not extract an ELF vmlinux: no gzip/xz/zstd/lz4/bzip2 payload found, \
         or the matching decompressor is not installed (install xz-utils for a \
         Debian kernel)"
    );
}

enum PipeError {
    /// The codec binary is not on PATH.
    Spawn,
    /// The codec ran but failed / produced nothing useful.
    Run,
}

/// Run `argv` (argv[0] = program), feeding `input` on stdin and returning stdout.
/// The decompressor's exit status is ignored — a bzImage's compressed stream is
/// followed by a small trailer, so a codec that flags trailing data still emits the
/// full vmlinux (matching `extract-vmlinux`); the caller validates the ELF magic.
fn pipe_through(argv: &[&str], input: &[u8]) -> std::result::Result<Vec<u8>, PipeError> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| PipeError::Spawn)?;
    // Write on a thread so a codec that starts emitting before consuming all input
    // cannot deadlock on full pipe buffers.
    let mut stdin = child.stdin.take().expect("stdin piped");
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // drop closes the pipe (EOF for the child)
    });
    let out = child.wait_with_output().map_err(|_| PipeError::Run)?;
    let _ = writer.join();
    if out.stdout.is_empty() {
        return Err(PipeError::Run);
    }
    Ok(out.stdout)
}

/// First offset of `needle` within `haystack`, if any.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Resolve wanted module basenames to their relative paths (under
/// `/lib/modules/<ver>`) from a `modules.dep` body, preserving the wanted order
/// and skipping any not present. Each `modules.dep` line is `path.ko:`
/// optionally followed by space-separated dependency paths; the leading token is
/// the module's own relative path, and its filename is `<name>.ko`.
fn resolve_module_paths(dep_text: &str, wanted: &[&str]) -> Vec<String> {
    // basename ("virtio_pci") -> relative path ("kernel/drivers/virtio/virtio_pci.ko")
    let mut by_name: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in dep_text.lines() {
        let path = match line.split_once(':') {
            Some((p, _)) => p.trim(),
            None => line.trim(),
        };
        if path.is_empty() {
            continue;
        }
        let file = path.rsplit('/').next().unwrap_or(path);
        if let Some(base) = file.strip_suffix(".ko") {
            by_name
                .entry(base.to_string())
                .or_insert_with(|| path.to_string());
        }
    }
    wanted
        .iter()
        .filter_map(|name| match by_name.get(*name) {
            Some(rel) => Some(rel.clone()),
            None => {
                eprintln!("virtkit: module {name} not in modules.dep — skipping");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_module_paths_orders_and_skips() {
        // A synthetic modules.dep: some wanted modules present (out of order and
        // with dependencies), some absent. crc16 and vmw_vsock_* are missing.
        let dep = "\
kernel/drivers/virtio/virtio.ko:
kernel/drivers/virtio/virtio_pci.ko: kernel/drivers/virtio/virtio_pci_modern_dev.ko kernel/drivers/virtio/virtio.ko
kernel/drivers/virtio/virtio_pci_modern_dev.ko:
kernel/drivers/block/virtio_blk.ko: kernel/drivers/virtio/virtio.ko
kernel/fs/ext4/ext4.ko: kernel/fs/jbd2/jbd2.ko kernel/fs/mbcache.ko
kernel/fs/jbd2/jbd2.ko:
kernel/fs/mbcache.ko:
kernel/net/vmw_vsock/vsock.ko:
";
        let wanted = &[
            "virtio",
            "virtio_ring", // absent -> skipped
            "virtio_pci_modern_dev",
            "virtio_pci",
            "virtio_blk",
            "crc16", // absent -> skipped
            "mbcache",
            "jbd2",
            "ext4",
            "vsock",
            "vmw_vsock_virtio_transport", // absent -> skipped
        ];
        let got = resolve_module_paths(dep, wanted);
        assert_eq!(
            got,
            vec![
                "kernel/drivers/virtio/virtio.ko".to_string(),
                "kernel/drivers/virtio/virtio_pci_modern_dev.ko".to_string(),
                "kernel/drivers/virtio/virtio_pci.ko".to_string(),
                "kernel/drivers/block/virtio_blk.ko".to_string(),
                "kernel/fs/mbcache.ko".to_string(),
                "kernel/fs/jbd2/jbd2.ko".to_string(),
                "kernel/fs/ext4/ext4.ko".to_string(),
                "kernel/net/vmw_vsock/vsock.ko".to_string(),
            ],
        );
    }

    #[test]
    fn resolve_module_paths_empty_when_none_match() {
        let dep = "kernel/foo/bar.ko:\nkernel/baz/qux.ko: kernel/foo/bar.ko\n";
        assert!(resolve_module_paths(dep, &["virtio", "ext4"]).is_empty());
    }

    #[test]
    fn extract_vmlinux_passes_through_elf() {
        // An already-ELF vmlinux is returned verbatim, no decompressor needed.
        let mut elf = ELF_MAGIC.to_vec();
        elf.extend_from_slice(b"\x02\x01\x01the rest of a vmlinux");
        assert_eq!(extract_vmlinux(&elf).unwrap(), elf);
    }

    #[test]
    fn find_subslice_hit_miss_and_empty() {
        assert_eq!(find_subslice(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abcdef", b"abc"), Some(0));
        assert_eq!(find_subslice(b"abcdef", b"ef"), Some(4));
        assert_eq!(find_subslice(b"abcdef", b"xy"), None);
        // Empty needle and a needle longer than the haystack both yield None.
        assert_eq!(find_subslice(b"abc", b""), None);
        assert_eq!(find_subslice(b"ab", b"abc"), None);
    }
}
