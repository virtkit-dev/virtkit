//! The preinit initramfs boot used whenever a `vk run` axis leaves the default:
//! `--kernel image` (boot the image's OWN modular kernel) and/or `--init
//! image`/`--init entrypoint` (hand PID 1 to the image's OWN init/systemd, or to its OWN
//! entrypoint). This module reads the image's ext4
//! host-side (no mount, via [`crate::ext4_read::Ext4Reader`]) and, for the image
//! kernel, extracts the two pieces libkrun needs: the raw kernel `vmlinuz` and the
//! boot-critical kernel modules. It then assembles the preinit initramfs the agent
//! boots from — the agent as `/init` plus any `.ko` files (decompressed from a distro's
//! `.ko.xz`/`.ko.zst`/`.ko.gz`) and an ordered load list — so the preinit can `insmod`
//! virtio/ext4 before mounting the real root and (for an image PID 1) exec'ing what that
//! axis names. With `--kernel default` the pinned
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
    // fuse + virtiofs so the preinit can mount --volume/--workdir host shares and the
    // compose control fs (--compose).
    "fuse",
    "virtiofs",
    // virtio_net and its failover dependencies provide eth0 for --net under libkrun.
    // Load order is explicit: dependencies are not followed through modules.dep.
    "failover",
    "net_failover",
    "virtio_net",
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
        let dep_text = String::from_utf8(reader.read_file(&dep_path, MAX_TEXT_BYTES)?)
            .with_context(|| format!("{dep_path} is not UTF-8"))?;
        let rel_paths = resolve_module_paths(&dep_text, WANTED_MODULES);

        for rel in &rel_paths {
            let abs_in_image = format!("/lib/modules/{ver}/{rel}");
            let raw = match reader.read_file(&abs_in_image, MAX_MODULE_BYTES) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("virtkit: skipping module {abs_in_image} (unreadable: {e:#})");
                    continue;
                }
            };
            // Modern distros ship compressed modules (Debian .ko.xz, others .ko.zst /
            // .ko.gz). The agent insmods raw .ko, so decompress here and store the module
            // under its plain .ko name (both in the initramfs and the load list).
            let (ko_rel, bytes) = match decompress_module(rel, raw, MAX_MODULE_BYTES) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("virtkit: skipping module {abs_in_image} ({e:#})");
                    continue;
                }
            };
            load_order_abs.push(format!("/lib/modules/{ver}/{ko_rel}"));
            modules.push((ko_rel, bytes));
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

// Caps on what an image — possibly a guest-written disk — can make the host allocate, by the
// size it gives a file or by what that file decompresses to. Each is far past any real one.
/// Maximum size of a kernel image, and separately of its decompressed payload.
const MAX_KERNEL_BYTES: u64 = 256 << 20;
/// Maximum size of a module, and separately of its decompressed output.
const MAX_MODULE_BYTES: u64 = 64 << 20;
/// Maximum `modules.dep` size.
const MAX_TEXT_BYTES: u64 = 16 << 20;
/// The most compressed-payload candidates tried in a kernel image, each a decompression: a real
/// bzImage holds one payload and few stray magics before it.
const MAX_PAYLOAD_CANDIDATES: usize = 16;

/// The image's raw kernel image bytes: `/boot/vmlinuz-<ver>`, falling back to the
/// sole `vmlinuz-*` regular file under `/boot`.
fn read_kernel(reader: &Ext4Reader, ver: &str) -> Result<Vec<u8>> {
    let exact = format!("/boot/vmlinuz-{ver}");
    if let Ok(bytes) = reader.read_file(&exact, MAX_KERNEL_BYTES) {
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
            reader.read_file(&path, MAX_KERNEL_BYTES)
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
/// matching decoder, accepting the first result that is an ELF. This mirrors the
/// kernel tree's `scripts/extract-vmlinux`, with the decoders built in: gzip, xz and
/// zstd, which cover the distributions' kernels.
fn extract_vmlinux(image: &[u8]) -> Result<Vec<u8>> {
    if image.starts_with(ELF_MAGIC) {
        return Ok(image.to_vec());
    }
    let mut candidates = 0;
    for (magic, codec) in CODECS {
        let mut from = 0;
        while let Some(off) = find_subslice(&image[from..], magic) {
            if candidates == MAX_PAYLOAD_CANDIDATES {
                bail!(
                    "no ELF vmlinux among the first {MAX_PAYLOAD_CANDIDATES} compressed \
                     payloads found in the kernel image"
                );
            }
            candidates += 1;
            let at = from + off;
            if let Some(out) = decode_payload(*codec, &image[at..], MAX_KERNEL_BYTES)
                && out.starts_with(ELF_MAGIC)
            {
                return Ok(out);
            }
            from = at + 1;
        }
    }
    if let Some((_, name)) = UNSUPPORTED_CODECS
        .iter()
        .find(|(magic, _)| find_subslice(image, magic).is_some())
    {
        bail!(
            "could not extract an ELF vmlinux: the kernel image looks {name}-compressed, \
             which vk does not decompress (gzip, xz and zstd only)"
        );
    }
    bail!(
        "could not extract an ELF vmlinux: no gzip, xz or zstd payload in the kernel image \
         decompresses to ELF"
    );
}

/// A supported kernel compression format.
#[derive(Clone, Copy, Debug)]
enum Codec {
    Gzip,
    Xz,
    Zstd,
}

/// The payloads vk decompresses, by magic, in the order extract-vmlinux probes them.
const CODECS: &[(&[u8], Codec)] = &[
    (&[0x1f, 0x8b, 0x08], Codec::Gzip),
    (&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], Codec::Xz),
    (&[0x28, 0xb5, 0x2f, 0xfd], Codec::Zstd),
];

/// The other formats a kernel may be compressed with, named in the error when only they match.
const UNSUPPORTED_CODECS: &[(&[u8], &str)] = &[
    (&[0x02, 0x21, 0x4c, 0x18], "lz4"),
    (&[0x42, 0x5a, 0x68], "bzip2"),
];

/// Decompress the payload at the start of `input`, retaining output on decoder errors:
/// a bzImage's small trailer can cause an error after the full vmlinux is decoded.
/// The caller checks the ELF magic. Return `None` for empty output or output over `max` bytes.
fn decode_payload(codec: Codec, input: &[u8], max: u64) -> Option<Vec<u8>> {
    let out = match codec {
        Codec::Gzip => read_lenient(flate2::read::GzDecoder::new(input), max)?,
        Codec::Zstd => read_lenient(
            zstd::stream::read::Decoder::new(input).ok()?.single_frame(),
            max,
        )?,
        // A kernel's xz stream uses the x86 BCJ filter, which lzma-rs (the modules') does
        // not decode.
        Codec::Xz => read_lenient(lzma_rust2::XzReader::new(input, false), max)?,
    };
    (!out.is_empty()).then_some(out)
}

/// Read until EOF or the first error, retaining output up to `max` bytes.
/// Return `None` if output exceeds `max`.
fn read_lenient(r: impl std::io::Read, max: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    let _ = r.take(max.saturating_add(1)).read_to_end(&mut out);
    (out.len() as u64 <= max).then_some(out)
}

/// First offset of `needle` within `haystack`, if any.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decompress a module read from the image if its `rel` path carries a compression
/// suffix, returning the plain `.ko` relative path and the raw module bytes. An
/// uncompressed `.ko` passes through unchanged. The agent insmods raw `.ko`, so this is
/// where a distro's `.ko.xz` / `.ko.zst` / `.ko.gz` becomes loadable.
///
/// The handled suffixes must stay in sync with the accepted list in
/// `resolve_module_paths`; a suffix accepted there but not here falls through as a
/// plain `.ko` and fails to load.
///
/// Errors once the output passes `max` bytes: a few compressed bytes can claim gigabytes.
fn decompress_module(rel: &str, raw: Vec<u8>, max: u64) -> Result<(String, Vec<u8>)> {
    if let Some(stem) = rel.strip_suffix(".xz") {
        let mut out = CappedWriter {
            buf: Vec::new(),
            max,
        };
        lzma_rs::xz_decompress(&mut &raw[..], &mut out).context("xz-decompressing module")?;
        Ok((stem.to_string(), out.buf))
    } else if let Some(stem) = rel.strip_suffix(".zst") {
        let dec =
            zstd::stream::read::Decoder::new(&raw[..]).context("zstd-decompressing module")?;
        let out = read_capped(dec, max).context("zstd-decompressing module")?;
        Ok((stem.to_string(), out))
    } else if let Some(stem) = rel.strip_suffix(".gz") {
        let out = read_capped(flate2::read::GzDecoder::new(&raw[..]), max)
            .context("gunzipping module")?;
        Ok((stem.to_string(), out))
    } else {
        Ok((rel.to_string(), raw))
    }
}

/// All of `r`, or an error once it passes `max` bytes.
fn read_capped(r: impl std::io::Read, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    r.take(max.saturating_add(1)).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        bail!("decompresses to over {max} bytes");
    }
    Ok(out)
}

/// A `Vec` sink that fails a write taking it past `max` bytes.
struct CappedWriter {
    buf: Vec<u8>,
    max: u64,
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if (self.buf.len() + data.len()) as u64 > self.max {
            return Err(std::io::Error::other(format!(
                "decompresses to over {} bytes",
                self.max
            )));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
        // Accept an optional compression suffix (Debian .ko.xz, others .ko.zst/.ko.gz)
        // so a modular distro kernel resolves; the compressed path is kept as the value
        // and decompressed at extraction time by `decompress_module` (keep the two
        // suffix lists in sync).
        let stem = file
            .strip_suffix(".xz")
            .or_else(|| file.strip_suffix(".zst"))
            .or_else(|| file.strip_suffix(".gz"))
            .unwrap_or(file);
        if let Some(base) = stem.strip_suffix(".ko") {
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
    fn resolve_module_paths_accepts_compressed() {
        // A modular distro kernel: .ko.xz (Debian), .ko.zst and .ko.gz all resolve, and
        // the compressed path is preserved for decompression at extraction time.
        let dep = "\
kernel/drivers/virtio/virtio.ko.xz:
kernel/drivers/block/virtio_blk.ko.xz: kernel/drivers/virtio/virtio.ko.xz
kernel/fs/ext4/ext4.ko.zst:
kernel/net/vmw_vsock/vsock.ko.gz:
";
        let got = resolve_module_paths(dep, &["virtio", "virtio_blk", "ext4", "vsock"]);
        assert_eq!(
            got,
            vec![
                "kernel/drivers/virtio/virtio.ko.xz".to_string(),
                "kernel/drivers/block/virtio_blk.ko.xz".to_string(),
                "kernel/fs/ext4/ext4.ko.zst".to_string(),
                "kernel/net/vmw_vsock/vsock.ko.gz".to_string(),
            ],
        );
    }

    #[test]
    fn decompress_module_plain_passthrough() {
        let raw = b"raw .ko bytes".to_vec();
        let (rel, out) = decompress_module("kernel/x/foo.ko", raw.clone(), u64::MAX).unwrap();
        assert_eq!(rel, "kernel/x/foo.ko");
        assert_eq!(out, raw);
    }

    #[test]
    fn decompress_module_gz_roundtrips() {
        use std::io::Write;
        let plain = b"fake ext4.ko payload".to_vec();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let (rel, out) =
            decompress_module("kernel/fs/ext4/ext4.ko.gz", enc.finish().unwrap(), u64::MAX)
                .unwrap();
        assert_eq!(rel, "kernel/fs/ext4/ext4.ko");
        assert_eq!(out, plain);
    }

    #[test]
    fn decompress_module_zst_roundtrips() {
        let plain = b"fake vsock.ko payload".to_vec();
        let z = zstd::encode_all(&plain[..], 0).unwrap();
        let (rel, out) = decompress_module("kernel/net/vsock.ko.zst", z, u64::MAX).unwrap();
        assert_eq!(rel, "kernel/net/vsock.ko");
        assert_eq!(out, plain);
    }

    #[test]
    fn decompress_module_xz_roundtrips() {
        // .ko.xz is the motivating Debian format and the only one using the pure-Rust
        // lzma-rs path, so pin a round-trip through its own encoder.
        let plain = b"fake virtio_blk.ko payload".to_vec();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut &plain[..], &mut xz).unwrap();
        let (rel, out) =
            decompress_module("kernel/drivers/block/virtio_blk.ko.xz", xz, u64::MAX).unwrap();
        assert_eq!(rel, "kernel/drivers/block/virtio_blk.ko");
        assert_eq!(out, plain);
    }

    /// Every compressed module format accepts output at the cap and rejects output above it.
    #[test]
    fn decompress_module_stops_at_its_cap() {
        use std::io::Write;
        let plain = vec![0u8; 64 << 10];
        let max = plain.len() as u64;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&plain).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(&plain[..], 0).unwrap();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut &plain[..], &mut xz).unwrap();
        for (rel, raw) in [("m.ko.gz", gz), ("m.ko.zst", zst), ("m.ko.xz", xz)] {
            assert_eq!(
                decompress_module(rel, raw.clone(), max).unwrap().1,
                plain,
                "{rel} at its cap"
            );
            assert!(
                decompress_module(rel, raw, max - 1).is_err(),
                "{rel} past its cap"
            );
        }
    }

    /// A fake vmlinux: the ELF magic, then x86 call and jump opcodes, which the BCJ filter
    /// rewrites, so a decoder that skipped the filter would return other bytes.
    fn fake_vmlinux() -> Vec<u8> {
        let mut elf = ELF_MAGIC.to_vec();
        for i in 0u32..4096 {
            elf.push(if i % 2 == 0 { 0xe8 } else { 0xe9 });
            elf.extend_from_slice(&(i * 7).to_le_bytes());
            elf.extend_from_slice(b"\x90\x90\xc3");
        }
        elf
    }

    /// Wrap `payload` in a bzImage setup stub and trailer.
    fn fake_bzimage(payload: &[u8]) -> Vec<u8> {
        let mut image = b"MZ setup stub, no payload magic here".to_vec();
        image.extend_from_slice(payload);
        image.extend_from_slice(&[0x00, 0x10, 0x3a, 0x01, 0xde, 0xad, 0xbe, 0xef]);
        image
    }

    fn xz_bcj(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut options = lzma_rust2::XzOptions::with_preset(6);
        options.prepend_pre_filter(lzma_rust2::FilterType::BcjX86, 0);
        let mut w = lzma_rust2::XzWriter::new(Vec::new(), options).unwrap();
        w.write_all(plain).unwrap();
        w.finish().unwrap()
    }

    /// Each built-in decoder extracts the vmlinux from a bzImage, its trailer included; the
    /// xz payload carries the x86 BCJ filter, as a Debian kernel's does.
    #[test]
    fn extract_vmlinux_decodes_each_payload() {
        use std::io::Write;
        let plain = fake_vmlinux();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&plain).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(&plain[..], 0).unwrap();
        for (name, payload) in [("gzip", gz), ("xz", xz_bcj(&plain)), ("zstd", zst)] {
            assert_eq!(
                extract_vmlinux(&fake_bzimage(&payload)).unwrap(),
                plain,
                "{name}"
            );
        }
    }

    /// Accept output at the cap; reject output above it.
    #[test]
    fn decode_payload_stops_at_its_cap() {
        let plain = fake_vmlinux();
        let max = plain.len() as u64;
        let payload = xz_bcj(&plain);
        assert_eq!(decode_payload(Codec::Xz, &payload, max), Some(plain));
        assert_eq!(decode_payload(Codec::Xz, &payload, max - 1), None);
    }

    /// A kernel compressed only in a format vk does not decode names that format.
    #[test]
    fn extract_vmlinux_names_an_unsupported_format() {
        let image = fake_bzimage(&[0x02, 0x21, 0x4c, 0x18, 1, 2, 3, 4]);
        let err = extract_vmlinux(&image).unwrap_err().to_string();
        assert!(err.contains("lz4"), "{err}");
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
