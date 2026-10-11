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
pub(crate) const PULLED_DISK: &str = "disk.vk_ro_img";
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

/// Whether the registry has layer `key`, without pulling it: the manifest digest that names it,
/// and what it was pushed with. A build takes a layer's password and licensing from here, and
/// pulls the layer only once something builds on it or boots it ([`pull`] with the digest).
pub(crate) fn remote(rg: &Registry, key: &str) -> Result<Option<(String, serde_json::Value)>> {
    Ok(crate::registry::fetch_bundle(rg, CACHE_REPO, &tag(key))?
        .map(|b| (b.digest, b.meta.unwrap_or_default())))
}

/// Pull layer `key` — the manifest `digest` names when given, else what its tag names now —
/// into the unpublished layer directory `tmp`, the chunks into the shared chunk cache under
/// `root`. Returns what the layer was pushed with, or `None` when the registry does not have it.
pub(crate) fn pull(
    rg: &Registry,
    root: &Path,
    key: &str,
    digest: Option<&str>,
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
        let reference = digest.map_or_else(|| tag(key), str::to_string);
        let Some(digest) =
            crate::registry::try_pull_ext4_lazy(rg, CACHE_REPO, &reference, &view, &label, None)?
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

/// The directories of the Windows cache rooted at `root` that hold one entry each, by key: a
/// layer, an install's settled base and the install itself, its medium, a fetched ISO.
fn entry_dirs(root: &Path) -> [PathBuf; 5] {
    let winiso = root.join("winiso");
    [
        root.join("layers"),
        winiso.join("settled"),
        winiso.join("install"),
        winiso.join("media"),
        winiso.join("iso"),
    ]
}

/// The [`crate::cachelock`] sidecars of the cache entry `dir`, beside it.
fn sidecars(dir: &Path) -> (PathBuf, PathBuf) {
    let name = dir.file_name().unwrap_or_default().to_string_lossy();
    (
        dir.with_file_name(format!("{name}.inuse")),
        dir.with_file_name(format!("{name}.used")),
    )
}

/// Reference the cache entry `dir` for as long as the guard lives, so [`gc`] leaves it.
pub(crate) fn reference(dir: &Path) -> Result<crate::cachelock::Guard> {
    // A first install references its entry before anything has made the directory holding it.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let (lock, used) = sidecars(dir);
    crate::cachelock::acquire_shared(&lock, &used)
}

/// Reference every entry of the Windows cache a disk stands on: `disk` itself when it is a
/// layer's, and each image down its backing chain, which ends at a pulled layer (it needs only
/// its chunks) or the install. For a bundle a job boots.
pub(crate) fn reference_chain(disk: &Path) -> Result<Vec<crate::cachelock::Guard>> {
    let mut guards = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut next = Some(disk.to_path_buf());
    while let Some(disk) = next.take() {
        let dir = disk.parent().context("a disk with no directory")?;
        let entry = dir
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str());
        if matches!(entry, Some("layers" | "settled" | "install")) && seen.insert(dir.to_path_buf())
        {
            guards.push(reference(dir)?);
        }
        if disk
            .extension()
            .is_some_and(|e| e == crate::registry::VK_RO_IMG_EXT)
        {
            break;
        }
        // A disk that is not a qcow2 (a raw image) stands on nothing.
        next = crate::qcow2::Qcow2::open(&disk)
            .ok()
            .and_then(|q| q.backing_path().map(Path::to_path_buf));
    }
    Ok(guards)
}

/// Reclaim what the Windows cache rooted at `root` has not used for `idle`: entries nobody
/// references ([`reference`]), then the chunks no pulled layer still reads. An entry is used
/// whenever a layer built on it is, as builds and jobs reference whole chains, so a layer is
/// never reclaimed from under one kept. Entries made before this sweep existed are dated now.
/// Best effort.
pub(crate) fn gc(root: &Path, idle: std::time::Duration) {
    let now = std::time::SystemTime::now();
    let mut freed = 0usize;
    for kind in entry_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&kind) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            let name = entry.file_name();
            // Keys only: no sidecar, no unpublished `<key>.tmp-<pid>`.
            if name.to_string_lossy().contains('.') || !dir.is_dir() {
                continue;
            }
            let (lock, used) = sidecars(&dir);
            if !used.exists() {
                crate::cachelock::stamp(&lock, &used);
                continue;
            }
            if crate::cachelock::try_reclaim(&lock, &used, idle, now, || {
                let _ = std::fs::remove_dir_all(&dir);
                let _ = std::fs::remove_file(&used);
            }) {
                freed += 1;
            }
        }
    }
    let chunks = sweep_chunks(root, idle, now);
    if freed > 0 || chunks > 0 {
        eprintln!(
            "virtkit: Windows cache: reclaimed {freed} entries and {chunks} chunks idle for {}s",
            idle.as_secs()
        );
    }
}

/// Remove the chunks under `root`'s chunk cache that no pulled layer reads and nothing wrote
/// for `idle` (a pull in progress writes its chunks before its view). Returns how many went.
fn sweep_chunks(root: &Path, idle: std::time::Duration, now: std::time::SystemTime) -> usize {
    let mut live = std::collections::HashSet::new();
    for kind in entry_dirs(root) {
        for entry in std::fs::read_dir(&kind).into_iter().flatten().flatten() {
            if let Ok(view) = std::fs::read(entry.path().join(PULLED_DISK)) {
                live.extend(view_chunks(&view));
            }
        }
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(root.join("registry").join("chunks"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| now.duration_since(t).unwrap_or_default() >= idle);
        if old && !live.contains(&name) && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The chunk file names (hex digests) the `.vk_ro_img` view `bytes` reads, as
/// `registry::write_vk_ro_img` lays it out; none for anything else.
fn view_chunks(bytes: &[u8]) -> Vec<String> {
    let parse = || -> Option<Vec<String>> {
        let magic = bytes.get(..8)?;
        if magic != crate::registry::VK_RO_IMG_MAGIC.as_slice() {
            return None;
        }
        let dir_len = u32::from_le_bytes(bytes.get(17..21)?.try_into().ok()?) as usize;
        let mut at = 21 + dir_len;
        let count = u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?);
        at += 8;
        let mut out = Vec::new();
        for _ in 0..count {
            // offset (8), length (4), codec (1), sha256 (32)
            let digest = bytes.get(at + 13..at + 45)?;
            out.push(digest.iter().map(|b| format!("{b:02x}")).collect());
            at += 45;
        }
        Some(out)
    };
    parse().unwrap_or_default()
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
        let meta = pull(&rg, &host_b, &key(2), None, &pulled).unwrap().unwrap();
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
        let meta = pull(&rg, &tmp.join("c"), &key(3), None, &again)
            .unwrap()
            .unwrap();
        assert_eq!(meta["password"], "pb");
        assert_eq!(contents(&layer_disk(&again), &tmp), contents(&next, &tmp));

        // A layer the registry does not have.
        let none = tmp.join("none");
        std::fs::create_dir_all(&none).unwrap();
        assert!(pull(&rg, &host_b, &key(9), None, &none).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A sweep dates what it finds undated, then reclaims what nobody references, keeps what a
    /// build or job references, and drops the chunks no pulled layer reads.
    #[test]
    fn a_sweep_keeps_what_is_referenced() {
        let root = std::env::temp_dir().join(format!("vk-wincache-gc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layers = root.join("layers");
        for dir in [
            layers.join(key(1)),
            layers.join(key(2)),
            root.join("winiso/settled").join(key(3)),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
        }
        // A pulled layer reading one of two cached chunks.
        let chunks = root.join("registry/chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        for c in [key(7), key(8)] {
            std::fs::write(chunks.join(c), b"chunk").unwrap();
        }
        let pulled = layers.join(key(4));
        crate::registry::write_vk_ro_img(
            &pulled.join(PULLED_DISK),
            4096,
            crate::registry::VK_RO_IMG_LAYOUT_FLAT,
            &chunks,
            &[crate::registry::LazyChunk {
                offset: 0,
                length: 4096,
                codec: crate::registry::VK_RO_IMG_CODEC_RAW,
                digest: [0x07; 32],
            }],
        )
        .unwrap();
        assert_eq!(
            view_chunks(&std::fs::read(pulled.join(PULLED_DISK)).unwrap()),
            [key(7)]
        );

        // Referenced before anything made its kind's directory, as a first install is.
        drop(reference(&root.join("winiso/media").join(key(5))).unwrap());

        let idle = std::time::Duration::ZERO;
        gc(&root, idle);
        assert!(
            layers.join(key(2)).exists(),
            "an undated entry is dated, not reclaimed"
        );

        let held = [
            reference(&layers.join(key(1))).unwrap(),
            reference(&pulled).unwrap(),
        ];
        assert!(crate::cachelock::reclaimed_eventually(|| {
            gc(&root, idle);
            !layers.join(key(2)).exists() && !root.join("winiso/settled").join(key(3)).exists()
        }));
        assert!(layers.join(key(1)).exists() && pulled.exists());
        assert!(chunks.join(key(7)).exists(), "a pulled layer's chunk stays");
        assert!(!chunks.join(key(8)).exists(), "an unread chunk goes");

        drop(held);
        assert!(crate::cachelock::reclaimed_eventually(|| {
            gc(&root, idle);
            !layers.join(key(1)).exists() && !pulled.exists()
        }));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A bundle's chain references each layer it stands on, down to the install, and stops at a
    /// pulled layer, which needs nothing under it.
    #[test]
    fn a_chain_references_every_layer_under_a_disk() {
        let root = std::env::temp_dir().join(format!("vk-wincache-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let install = root.join("winiso/install").join(key(1));
        let step = root.join("layers").join(key(2));
        let bundle = root.join("job/win-dc");
        for dir in [&install, &step, &bundle] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let raw = install.join("disk.raw");
        std::fs::write(&raw, vec![0u8; 1 << 20]).unwrap();
        crate::qcow2::create_overlay(&install.join(BUILT_DISK), &raw).unwrap();
        crate::qcow2::create_overlay(&step.join(BUILT_DISK), &install.join(BUILT_DISK)).unwrap();
        crate::qcow2::create_overlay(&bundle.join("disk.qcow2"), &step.join(BUILT_DISK)).unwrap();
        // The bundle's own dir is the job's, not the cache's: two references, step and install.
        assert_eq!(
            reference_chain(&bundle.join("disk.qcow2")).unwrap().len(),
            2
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
