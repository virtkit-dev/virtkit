//! Boot a persistent disk on the kernel installed in its own `/boot` (`vk run --boot-disk`,
//! experimental; see `docs/vm-boot-from-disk-design.md`, phase 1).
//!
//! On the GPT disk, the host reads the ext2 XBOOTLDR partition. Only the guest mounts
//! the x86-64 Linux root partition. On each launch, [`resolve`] selects the newest complete
//! `vmlinuz-<release>`/`initrd.img-<release>` pair in `/boot`. The kernel unpacks vk's
//! archive after the guest initrd, so the agent becomes `/init` and uses the guest's
//! `modprobe` to load the listed modules for that release. The archive also carries the
//! boot config.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::diskimg::DiskImage;
use crate::ext4_read::{Ext4Reader, FileType};
use crate::gpt;

/// Bound host memory use when reading a guest initrd. Distro initrds with firmware can reach tens of MB.
const MAX_INITRD_BYTES: u64 = 512 << 20;

/// Disk and archive used to resolve `/boot` for the initial launch and each reset.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BootDisk {
    /// The machine's disk, attached as `/dev/vda`.
    pub disk: PathBuf,
    /// vk's archive, appended to the guest's initrd.
    pub vk_cpio: PathBuf,
}

/// Kernel release selected for one launch.
#[derive(Debug)]
pub struct Resolved {
    pub release: String,
}

/// The root partition's index on `disk`, for the guest's `/dev/vda<N>`.
pub fn root_partition(disk: &Path) -> Result<u32> {
    let img = DiskImage::open(disk)?;
    let parts = gpt::read(&img).with_context(|| format!("{}", disk.display()))?;
    Ok(gpt::only_of_type(&parts, gpt::TYPE_ROOT_X86_64)?.index)
}

/// Write the newest complete pair from `/boot` to `kernel_out` and `initramfs_out`,
/// extracting an ELF vmlinux and appending vk's archive to the initrd. Read all inputs
/// before writing either output. A write failure can leave the outputs incomplete.
pub fn resolve(bd: &BootDisk, kernel_out: &Path, initramfs_out: &Path) -> Result<Resolved> {
    let name = bd.disk.display().to_string();
    // One open for the table and the filesystem both, so they describe the same image.
    let img = DiskImage::open(&bd.disk)?;
    let parts = gpt::read(&img).with_context(|| name.clone())?;
    let boot = gpt::only_of_type(&parts, gpt::TYPE_XBOOTLDR).with_context(|| name.clone())?;
    let index = boot.index;
    let fs = img.slice(boot.offset, boot.len)?;
    let reader = Ext4Reader::open_image(fs, &format!("{name} partition {index}"))?;
    let entries = reader.list_dir("/").context("listing /boot")?;
    let release = newest_pair(&entries)?;

    let raw = reader.read_file(
        &format!("/vmlinuz-{release}"),
        crate::fullvm::MAX_KERNEL_BYTES,
    )?;
    let elf = crate::fullvm::extract_vmlinux(&raw)
        .with_context(|| format!("extracting the ELF vmlinux of vmlinuz-{release}"))?;
    let initrd = reader.read_file(&format!("/initrd.img-{release}"), MAX_INITRD_BYTES)?;
    let vk =
        std::fs::read(&bd.vk_cpio).with_context(|| format!("reading {}", bd.vk_cpio.display()))?;

    std::fs::write(kernel_out, &elf)
        .with_context(|| format!("writing {}", kernel_out.display()))?;
    std::fs::write(initramfs_out, append_archive(initrd, &vk))
        .with_context(|| format!("writing {}", initramfs_out.display()))?;
    Ok(Resolved { release })
}

/// Align the appended cpio archive to the 4-byte boundary the kernel expects.
fn append_archive(mut initrd: Vec<u8>, archive: &[u8]) -> Vec<u8> {
    initrd.resize(initrd.len().next_multiple_of(4), 0);
    initrd.extend_from_slice(archive);
    initrd
}

/// Modules the agent loads before it mounts the root: the image-kernel boot's own, plus
/// the root's btrfs.
fn modprobe_list() -> Vec<&'static str> {
    crate::fullvm::WANTED_MODULES
        .iter()
        .chain(crate::fullvm::root_fs_modules("btrfs"))
        .copied()
        .collect()
}

/// Package the agent as `/init`, the boot config and module names. The guest initrd supplies the modules.
pub fn build_vk_cpio(agent: &Path, cfg: &vk_core::runcfg::RunConfig, out: &Path) -> Result<()> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut cpio = crate::cpio::CpioWriter::new(std::io::BufWriter::new(file));
    let f = std::fs::File::open(agent).with_context(|| format!("opening {}", agent.display()))?;
    let size = u32::try_from(f.metadata()?.len()).context("the agent exceeds the cpio format")?;
    cpio.file("init", 0o755, size, f)?;
    cpio.file_bytes(
        vk_core::runcfg::MODPROBE_LIST,
        0o644,
        modprobe_list().join("\n").as_bytes(),
    )?;
    cpio.file_bytes(
        vk_core::runcfg::INITRAMFS_PATH,
        0o600,
        cfg.to_json().as_bytes(),
    )?;
    cpio.finish()?;
    Ok(())
}

/// Select the newest matching regular files. The host prints the guest-provided release,
/// so accept only ASCII letters, digits and `._+~-` in a nonempty suffix.
fn newest_pair(entries: &[(String, FileType)]) -> Result<String> {
    let release_char = |c: char| c.is_ascii_alphanumeric() || "._+~-".contains(c);
    let files = |prefix: &str| -> Vec<String> {
        entries
            .iter()
            .filter(|(_, t)| *t == FileType::Regular)
            .filter_map(|(n, _)| n.strip_prefix(prefix))
            .filter(|r| !r.is_empty() && r.chars().all(release_char))
            .map(str::to_string)
            .collect()
    };
    let initrds = files("initrd.img-");
    let mut releases: Vec<String> = files("vmlinuz-")
        .into_iter()
        .filter(|r| initrds.contains(r))
        .collect();
    releases.sort_by(|a, b| version_cmp(a, b));
    match releases.pop() {
        Some(r) => Ok(r),
        None => bail!("no vmlinuz-<release> with a matching initrd.img-<release> in /boot"),
    }
}

/// Compare whole release suffixes using dpkg's `verrevcmp` ordering. Compare digit runs
/// by value. In non-digit runs, `~` sorts before the end and letters before punctuation.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let order = |c: Option<&u8>| -> i32 {
        match c {
            None => 0,
            Some(b'~') => -1,
            Some(c) if c.is_ascii_digit() => 0,
            Some(c) if c.is_ascii_alphabetic() => i32::from(*c),
            Some(c) => i32::from(*c) + 256,
        }
    };
    let digit = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let (ac, bc) = (order(a.get(i)), order(b.get(j)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = std::cmp::Ordering::Equal;
        while digit(a, i) && digit(b, j) {
            if first_diff.is_eq() {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return std::cmp::Ordering::Greater;
        }
        if digit(b, j) {
            return std::cmp::Ordering::Less;
        }
        if !first_diff.is_eq() {
            return first_diff;
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_sort_by_version() {
        let mut v = vec![
            "6.12.9+deb13-amd64",
            "6.12.48+deb13-amd64",
            "6.1.0-10-amd64",
            "6.1.0-9-amd64",
            "6.12.48+deb13-amd64~rc1",
        ];
        v.sort_by(|a, b| version_cmp(a, b));
        assert_eq!(
            v,
            [
                "6.1.0-9-amd64",
                "6.1.0-10-amd64",
                "6.12.9+deb13-amd64",
                "6.12.48+deb13-amd64~rc1",
                "6.12.48+deb13-amd64",
            ]
        );
    }

    #[test]
    fn the_newest_complete_pair_wins() {
        let e = |n: &str, t| (n.to_string(), t);
        let entries = [
            e("vmlinuz-6.1.0-9-amd64", FileType::Regular),
            e("initrd.img-6.1.0-9-amd64", FileType::Regular),
            e("vmlinuz-6.1.0-10-amd64", FileType::Regular),
            e("initrd.img-6.1.0-10-amd64", FileType::Regular),
            // newer, but its initrd is missing: an interrupted install
            e("vmlinuz-6.1.0-11-amd64", FileType::Regular),
            // a symlink is no pair
            e("vmlinuz-6.1.0-12-amd64", FileType::Symlink),
            e("initrd.img-6.1.0-12-amd64", FileType::Regular),
        ];
        assert_eq!(newest_pair(&entries).unwrap(), "6.1.0-10-amd64");
        assert!(newest_pair(&entries[4..]).is_err());
        // A name a terminal would act on is no release.
        let escape = [
            e("vmlinuz-9.9\x1b[2J", FileType::Regular),
            e("initrd.img-9.9\x1b[2J", FileType::Regular),
        ];
        assert!(newest_pair(&escape).is_err());
    }

    #[test]
    fn vk_archive_follows_the_initrd_on_a_4_byte_boundary() {
        assert_eq!(append_archive(b"abcde".to_vec(), b"XY"), b"abcde\0\0\0XY");
        assert_eq!(append_archive(b"abcd".to_vec(), b"XY"), b"abcdXY");
    }

    #[test]
    fn vk_archive_holds_the_agent_the_module_list_and_the_config() {
        let dir = std::env::temp_dir().join(format!("vk-bootdisk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let agent = dir.join("agent");
        vk_fs::write_new(&agent, b"AGENT", 0o600).unwrap();
        let out = dir.join("vk.cpio");
        build_vk_cpio(&agent, &vk_core::runcfg::RunConfig::default(), &out).unwrap();
        let cpio = std::fs::read(&out).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(cpio.starts_with(b"070701"));
        let has = |needle: &[u8]| cpio.windows(needle.len()).any(|w| w == needle);
        for name in [
            "init",
            vk_core::runcfg::MODPROBE_LIST,
            vk_core::runcfg::INITRAMFS_PATH,
            "TRAILER!!!",
        ] {
            assert!(has(name.as_bytes()), "{name}");
        }
        assert!(has(b"AGENT") && has(b"btrfs") && has(b"virtio_pci"));
    }
}
