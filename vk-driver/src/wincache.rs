//! Windows layers in the build cache registry, so the hosts sharing one build an install and
//! each `RUN`/`COPY` once between them, as Linux build steps are shared.
//!
//! A layer is pushed as the build cache pushes a Linux step: chunked by content (FastCDC),
//! each chunk stored once registry-wide, under `build-cache:win-<key>`. A layer whose parent
//! came from or went to the registry is pushed as a diff: the parent's chunks are reused, and
//! only the ranges the step wrote are chunked again. A host missing a layer pulls it lazily: a
//! `.vk_ro_img` view over the chunks, fetched now and decompressed as Windows reads them, which
//! the next step's overlay builds on. A pulled layer stands alone; it needs none of the layers
//! under it, here or anywhere.
//!
//! The config of each entry carries what the build needs beside the disk: the Administrator
//! password the layer's install was given (two hosts installing the same key concurrently get
//! different ones, so each layer records its own) and Windows' licensing, when it was read.
//!
//! While a host makes a layer it holds the registry's build lock on its key, so the others
//! wait for its push instead of installing Windows again.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::Registry;

const CACHE_REPO: &str = vk_registry::BUILD_CACHE_REPO;
/// The disk of a layer this host made: a qcow2 overlay over its parent's.
pub(crate) const BUILT_DISK: &str = "disk.qcow2";
/// The disk of a layer pulled from the registry: a lazy view over its chunks.
const PULLED_DISK: &str = "disk.vk_ro_img";
/// In a layer's directory: the registry manifest the layer's disk is, byte for byte, when it
/// was pulled from or pushed to the registry. Only then can a child's push reuse its chunks.
const DIGEST: &str = "registry-digest";
/// In a layer's directory: the Administrator password of a layer that recorded one.
const PASSWORD: &str = "admin-password";

/// The registry tag of layer `key`.
fn tag(key: &str) -> String {
    format!("win-{key}")
}

/// The disk of the layer whose directory is `dir`, built here or pulled.
pub(crate) fn layer_disk(dir: &Path) -> PathBuf {
    let pulled = dir.join(PULLED_DISK);
    if pulled.exists() {
        pulled
    } else {
        dir.join(BUILT_DISK)
    }
}

/// The password the layer in `dir` recorded, if it recorded one.
pub(crate) fn password(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(PASSWORD))
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
}

/// Record `password` in the layer directory `dir` (still unpublished), readable by its owner
/// only.
pub(crate) fn write_password(dir: &Path, password: &str) -> Result<()> {
    let path = dir.join(PASSWORD);
    let _ = std::fs::remove_file(&path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("writing {}", path.display()))?;
    std::io::Write::write_all(&mut file, password.as_bytes())?;
    Ok(())
}

/// Take the fleet's build lock on layer `key`, waiting while another host makes it. `None`
/// without a lock server (a local store) or when the wait runs out: the build then goes on
/// uncoordinated.
pub(crate) fn lock(rg: &Registry, key: &str, what: &str) -> Option<crate::registry::BuildLock> {
    crate::registry::build_lock(rg, &format!("{CACHE_REPO}/{}", tag(key)), &mut |holder| {
        eprintln!(
            "virtkit:   {what} {}: waiting for {holder}, which makes it",
            &key[..12]
        );
    })
}

/// Pull layer `key` into the unpublished layer directory `tmp`, the chunks into the shared
/// chunk cache under `root`. Returns what the layer was pushed with, or `None` when the
/// registry does not have it.
pub(crate) fn pull(
    rg: &Registry,
    root: &Path,
    key: &str,
    tmp: &Path,
) -> Result<Option<serde_json::Value>> {
    // The chunk cache is `<staging>/../chunks` (see `registry::chunks_cache_dir`): one cache for
    // every Windows layer, whichever directory the layer itself ends up in.
    let staging = root
        .join("registry")
        .join(format!("{key}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
    let result = (|| -> Result<Option<serde_json::Value>> {
        let view = staging.join(PULLED_DISK);
        let label = format!("Windows layer {}", &key[..12]);
        let Some(digest) =
            crate::registry::try_pull_ext4_lazy(rg, CACHE_REPO, &tag(key), &view, &label, None)?
        else {
            return Ok(None);
        };
        // By digest: the tag may have moved since.
        let meta = crate::registry::fetch_bundle(rg, CACHE_REPO, &digest)?
            .with_context(|| format!("{label}: {digest} vanished from the registry"))?
            .meta
            .unwrap_or_default();
        std::fs::rename(&view, tmp.join(PULLED_DISK))
            .with_context(|| format!("placing {} in {}", view.display(), tmp.display()))?;
        std::fs::write(tmp.join(DIGEST), &digest)?;
        if let Some(password) = meta["password"].as_str() {
            write_password(tmp, password)?;
        }
        Ok(Some(meta))
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

/// Push the layer `key` whose disk is `disk`, a qcow2 overlay in the published layer directory,
/// with `meta`; `parent` is the directory of the layer under it, `None` for an install. Records
/// the manifest's digest in the layer's directory. A diff over the parent's chunks when the
/// parent is in the registry as this host has it, the whole chain otherwise.
pub(crate) fn push(
    rg: &Registry,
    key: &str,
    disk: &Path,
    parent: Option<&Path>,
    meta: serde_json::Value,
) -> Result<String> {
    let (dirty, holes, total_size) = {
        let mut q = crate::qcow2::Qcow2::open(disk)?;
        let (data, zero) = q.own_extents()?;
        (data, zero, q.virtual_size())
    };
    let parent_layers = match parent.and_then(|dir| std::fs::read_to_string(dir.join(DIGEST)).ok())
    {
        Some(digest) => crate::registry::fetch_bundle(rg, CACHE_REPO, digest.trim())?
            .filter(|b| b.total_size == total_size)
            .map(|b| b.chunks)
            .unwrap_or_default(),
        None => Vec::new(),
    };
    eprintln!(
        "virtkit:   pushing layer {} to the build cache ({})",
        &key[..12],
        if parent_layers.is_empty() {
            "whole disk"
        } else {
            "diff"
        }
    );
    let (_, _, digest) = crate::registry::push_disk_diff(
        rg,
        CACHE_REPO,
        &tag(key),
        disk,
        // The registry's only boot kind: the entry is a disk, as a Linux build step's is.
        crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk),
        total_size,
        &dirty,
        &holes,
        &parent_layers,
        Some(meta),
    )?;
    if let Some(dir) = disk.parent() {
        let tmp = dir.join(format!("{DIGEST}.tmp-{}", std::process::id()));
        std::fs::write(&tmp, &digest)?;
        std::fs::rename(&tmp, dir.join(DIGEST))?;
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const SIZE: u64 = 8 << 20;

    fn have(tool: &str) -> bool {
        Command::new(tool).arg("--version").output().is_ok()
    }

    /// Write `len` bytes of `pattern` at `off` into the qcow2 `img`, as a guest would.
    fn write(img: &Path, pattern: u8, off: u64, len: u64) {
        let ok = Command::new("qemu-io")
            .args(["-c", &format!("write -P {pattern} {off} {len}")])
            .arg(img)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "qemu-io write into {}", img.display());
    }

    /// Every byte of `disk`, a qcow2 or, through an overlay over it, a `.vk_ro_img`.
    fn contents(disk: &Path, scratch: &Path) -> Vec<u8> {
        let disk = if disk.extension().is_some_and(|e| e == "vk_ro_img") {
            let ovl = scratch.join(format!(
                "read-{}.qcow2",
                disk.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
            ));
            let _ = std::fs::remove_file(&ovl);
            crate::qcow2::create_overlay(&ovl, disk).unwrap();
            ovl
        } else {
            disk.to_path_buf()
        };
        let mut q = crate::qcow2::Qcow2::open(&disk).unwrap();
        let mut buf = vec![0u8; q.virtual_size() as usize];
        q.read_at(0, &mut buf).unwrap();
        buf
    }

    fn key(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    /// A pulled layer reads as the layer pushed, a step pushed over a pushed or pulled parent
    /// as a diff reads back whole, and each layer carries its own password.
    #[test]
    fn layers_round_trip_through_the_registry() {
        if !have("qemu-io") {
            eprintln!("skipping: qemu-io not available");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("vk-wincache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let host_a = tmp.join("a");
        let host_b = tmp.join("b");
        for dir in [&host_a, &host_b] {
            std::fs::create_dir_all(dir.join("layers")).unwrap();
        }
        let rg = Registry::for_share(
            tmp.join("store").display().to_string(),
            false,
            None,
            String::new(),
            None,
            None,
            None,
        );

        // Host A installs: a raw disk with data under an overlay the install wrote into.
        let raw = host_a.join("install.raw");
        let mut bytes = vec![0u8; SIZE as usize];
        for (i, b) in bytes.iter_mut().enumerate().take(3 << 20) {
            *b = (i * 7 % 251) as u8 + 1;
        }
        std::fs::write(&raw, &bytes).unwrap();
        let base_dir = host_a.join("layers").join(key(1));
        std::fs::create_dir_all(&base_dir).unwrap();
        let base = base_dir.join(BUILT_DISK);
        crate::qcow2::create_overlay(&base, &raw).unwrap();
        write(&base, 0x11, 4 << 20, 1 << 20);
        push(
            &rg,
            &key(1),
            &base,
            None,
            serde_json::json!({"password": "pa"}),
        )
        .unwrap();
        assert!(base_dir.join(DIGEST).exists());

        // A step over it, pushed as a diff over the base's chunks.
        let step_dir = host_a.join("layers").join(key(2));
        std::fs::create_dir_all(&step_dir).unwrap();
        let step = step_dir.join(BUILT_DISK);
        crate::qcow2::create_overlay(&step, &base).unwrap();
        write(&step, 0x22, 1 << 20, 64 << 10);
        write(&step, 0x33, 6 << 20, 1 << 20);
        push(
            &rg,
            &key(2),
            &step,
            Some(&base_dir),
            serde_json::json!({"password": "pa"}),
        )
        .unwrap();

        // Host B pulls the step alone, and gets every byte of it.
        let pulled = host_b.join("layers").join(key(2));
        std::fs::create_dir_all(&pulled).unwrap();
        let meta = pull(&rg, &host_b, &key(2), &pulled).unwrap().unwrap();
        assert_eq!(meta["password"], "pa");
        assert_eq!(password(&pulled).as_deref(), Some("pa"));
        assert!(layer_disk(&pulled).ends_with(PULLED_DISK));
        assert_eq!(contents(&layer_disk(&pulled), &tmp), contents(&step, &tmp));

        // Host B makes a step over the pulled one, with a password of its own; its diff push
        // reuses the pulled layer's chunks and still reads back whole.
        let next_dir = host_b.join("layers").join(key(3));
        std::fs::create_dir_all(&next_dir).unwrap();
        let next = next_dir.join(BUILT_DISK);
        crate::qcow2::create_overlay(&next, &layer_disk(&pulled)).unwrap();
        write(&next, 0x44, 2 << 20, 128 << 10);
        push(
            &rg,
            &key(3),
            &next,
            Some(&pulled),
            serde_json::json!({"password": "pb"}),
        )
        .unwrap();
        let again = tmp.join("c").join(key(3));
        std::fs::create_dir_all(&again).unwrap();
        let meta = pull(&rg, &tmp.join("c"), &key(3), &again).unwrap().unwrap();
        assert_eq!(meta["password"], "pb");
        assert_eq!(contents(&layer_disk(&again), &tmp), contents(&next, &tmp));

        // A layer the registry does not have.
        let none = tmp.join("none");
        std::fs::create_dir_all(&none).unwrap();
        assert!(pull(&rg, &host_b, &key(9), &none).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
