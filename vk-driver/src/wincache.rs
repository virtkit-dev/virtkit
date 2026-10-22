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
//! Each entry's config records its install's Administrator password and Windows' licensing,
//! when read. Concurrent installs of the same key get different passwords, so each layer
//! records its own.
//!
//! While a host makes a layer it holds the registry's build lock on its key, so the others
//! wait for its push instead of installing Windows again, for up to [`LOCK_WAIT`].

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

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

/// What looking a layer up in the build cache found. `Failed` has been warned of: the build
/// goes on as if the registry lacked the layer, best effort as a push is.
pub(crate) enum Lookup<T> {
    Found(T),
    Missing,
    Failed,
}

#[cfg(test)]
impl<T> Lookup<T> {
    /// What was found, missing and failed alike `None`.
    pub(crate) fn found(self) -> Option<T> {
        match self {
            Lookup::Found(t) => Some(t),
            Lookup::Missing | Lookup::Failed => None,
        }
    }
}

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
pub(crate) fn password(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(PASSWORD);
    match std::fs::read_to_string(&path) {
        Ok(p) => Ok(Some(p.trim().to_string()).filter(|p| !p.is_empty())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Record `password` in the unpublished layer directory `dir`, readable only by its owner.
pub(crate) fn write_password(dir: &Path, password: &str) -> Result<()> {
    let path = dir.join(PASSWORD);
    // A record left by an earlier attempt in this unpublished directory; absent is the norm.
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

/// How long a host waits for another to make a layer: longer than a Windows 11 install with
/// its settle, the longest step there is. A holder that dies loses its lease long before.
pub(crate) const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(3 * 3600);

/// Take the fleet's build lock on layer `key`, waiting while another host makes it. `None`
/// without a lock server (a local store) or when the wait runs out: the build then goes on
/// uncoordinated, and says so.
pub(crate) fn lock(rg: &Registry, key: &str, what: &str) -> Option<crate::registry::BuildLock> {
    let mut waited = false;
    let lock = crate::registry::build_lock_waiting(
        rg,
        &format!("{CACHE_REPO}/{}", tag(key)),
        LOCK_WAIT,
        &mut |holder| {
            waited = true;
            eprintln!(
                "virtkit:   {what} {}: waiting for {holder}, which makes it",
                &key[..12]
            );
        },
    );
    if waited && lock.is_none() {
        eprintln!(
            "virtkit: warning: {what} {}: gave up waiting after {}h; making it here too",
            &key[..12],
            LOCK_WAIT.as_secs() / 3600
        );
    }
    lock
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
    // A leftover of an earlier pull by a process that had this pid.
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
    let result = (|| -> Result<Option<serde_json::Value>> {
        let view = staging.join(PULLED_DISK);
        let label = format!("Windows layer {}", &key[..12]);
        let reference = digest.map_or_else(|| tag(key), str::to_string);
        // The view outlives this process, so it takes no lease: over a local store, what keeps
        // its chunks is the layer's `win-` tag, which `vk gc` never drops, but which a store gc
        // that does not keep that prefix — `vk registry gc`, `vk-registry gc`, a hub-run gc —
        // drops past its retention like any other.
        let Some(crate::registry::LazyView { digest, .. }) = crate::registry::try_pull_ext4_lazy(
            rg, CACHE_REPO, &reference, &view, &label, None, None,
        )?
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
        std::fs::write(tmp.join(DIGEST), &digest)
            .with_context(|| format!("writing {}", tmp.join(DIGEST).display()))?;
        if let Some(password) = meta["password"].as_str() {
            write_password(tmp, password)?;
        }
        Ok(Some(meta))
    })();
    // Best effort: a staging dir left behind costs disk, not correctness.
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
        // Best effort: a parent the registry cannot give back now makes a whole-disk push,
        // not a failed one.
        Some(digest) => crate::registry::fetch_bundle(rg, CACHE_REPO, digest.trim())
            .ok()
            .flatten()
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
    let dir = disk.parent().context("a layer disk with no directory")?;
    let tmp = dir.join(format!("{DIGEST}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, &digest).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, dir.join(DIGEST))
        .with_context(|| format!("renaming {} into place", tmp.display()))?;
    Ok(digest)
}

/// The kinds of entry of the Windows cache rooted at `root` whose disk can stand on another
/// entry's: a layer, an install's settled base, the install itself.
fn chained_kinds(root: &Path) -> [PathBuf; 3] {
    let winiso = root.join("winiso");
    [
        root.join("layers"),
        winiso.join("settled"),
        winiso.join("install"),
    ]
}

/// The directories of the Windows cache rooted at `root` that hold one entry each, by key: the
/// [`chained_kinds`], an install's medium, a fetched ISO.
fn entry_dirs(root: &Path) -> [PathBuf; 5] {
    let [layers, settled, install] = chained_kinds(root);
    let winiso = root.join("winiso");
    [
        layers,
        settled,
        install,
        winiso.join("media"),
        winiso.join("iso"),
    ]
}

/// The [`crate::cachelock`] sidecars of the cache entry `dir`, beside it.
fn sidecars(dir: &Path) -> (PathBuf, PathBuf) {
    let name = dir.file_name().unwrap_or_default();
    let beside = |suffix: &str| {
        let mut n = name.to_os_string();
        n.push(suffix);
        dir.with_file_name(n)
    };
    (beside(".inuse"), beside(".used"))
}

/// Reference the cache entry `dir` for as long as the guard lives, so [`gc`] leaves it. Taken
/// before the entry is looked at, so a sweep cannot reclaim it between the look and the use.
pub(crate) fn reference(dir: &Path) -> Result<crate::cachelock::Guard> {
    // A first install references its entry before anything has made the directory holding it.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let (lock, used) = sidecars(dir);
    crate::cachelock::acquire_shared(&lock, &used)
}

/// The references a build or a job holds on entries of the Windows cache, one per entry, for
/// as long as this lives or the guards it hands over do.
#[derive(Default)]
pub(crate) struct Refs(
    std::cell::RefCell<std::collections::BTreeMap<PathBuf, crate::cachelock::Guard>>,
);

impl Refs {
    /// Reference the entry `dir` ([`reference`]), unless this holds it already.
    pub(crate) fn reference(&self, dir: &Path) -> Result<()> {
        if self.0.borrow().contains_key(dir) {
            return Ok(());
        }
        let guard = reference(dir)?;
        self.0.borrow_mut().insert(dir.to_path_buf(), guard);
        Ok(())
    }

    /// Reference every entry of the Windows cache rooted at `root` that `disk` stands on
    /// ([`walk_chain`]), each before its disk is opened. One a sweep took since it was found is
    /// an error: a later build of its key could make a disk over it read other bytes. For a
    /// bundle a job boots, or a disk a build builds on.
    pub(crate) fn reference_chain(&self, root: &Path, disk: &Path) -> Result<()> {
        walk_chain(root, disk, &mut Vec::new(), |entry| {
            self.reference(entry)?;
            match std::fs::metadata(entry) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                    "{} is gone from the Windows build cache; build again",
                    entry.display()
                ),
                Err(e) => Err(e).with_context(|| format!("looking at {}", entry.display())),
            }
        })
    }

    /// Drop this reference to the entry `dir`, if it holds one.
    pub(crate) fn release(&self, dir: &Path) {
        self.0.borrow_mut().remove(dir);
    }

    /// Whether this references the entry `dir`.
    #[cfg(test)]
    pub(crate) fn holds(&self, dir: &Path) -> bool {
        self.0.borrow().contains_key(dir)
    }

    /// The references, for a caller that keeps them past the build or job that took them.
    pub(crate) fn into_guards(self) -> Vec<crate::cachelock::Guard> {
        self.0.into_inner().into_values().collect()
    }
}

/// Walk `disk`'s backing chain in the Windows cache rooted at `root`. Pass each entry under
/// [`chained_kinds`] to `enter` before opening its disk, then add it to `entries` once.
/// Stop at a disk with no backing, including a pulled layer, which needs only its chunks.
/// An unreadable disk returns an error with the preceding entries retained: its backing is
/// unknown, not absent.
fn walk_chain(
    root: &Path,
    disk: &Path,
    entries: &mut Vec<PathBuf>,
    mut enter: impl FnMut(&Path) -> Result<()>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let kinds = chained_kinds(root);
    let mut visited = std::collections::HashSet::new();
    let mut next = Some(disk.to_path_buf());
    while let Some(disk) = next.take() {
        if let Some(entry) = entry_of(&kinds, &disk)
            && !entries.contains(&entry)
        {
            enter(&entry)?;
            entries.push(entry);
        }
        let meta =
            std::fs::metadata(&disk).with_context(|| format!("opening {}", disk.display()))?;
        if !visited.insert((meta.dev(), meta.ino())) {
            bail!("{}: its backing chain loops", disk.display());
        }
        next = crate::qcow2::backing_name(&disk)?;
    }
    Ok(())
}

/// The entry of one of `kinds` that `disk` lies in, named as the cache names it: matched by
/// identity, not spelling, as a backing path may name the cache through another path. A kind
/// that cannot be looked at matches nothing.
fn entry_of(kinds: &[PathBuf], disk: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let dir = disk.parent()?;
    let (parent, name) = (dir.parent()?, dir.file_name()?);
    let id = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let parent = id(parent)?;
    kinds
        .iter()
        .find(|kind| id(kind) == Some(parent))
        .map(|kind| kind.join(name))
}

/// Hold the chunk store of the Windows cache rooted at `root` for a pull, from before its first
/// chunk until its view is published under its entry's name: [`gc`] sweeps the store only while
/// no pull holds it, so it never takes a chunk a view it has yet to see reads. Only Windows
/// pulls fill this store (`registry::chunks_cache_dir` under `root`); a Linux pull fills
/// `<state_dir>/registry/chunks`, which `image::sweep_chunks` sweeps by the `chunks.list` each
/// pull writes first, and takes no such lock.
pub(crate) fn hold_chunks(root: &Path) -> Result<crate::cachelock::Guard> {
    let registry = root.join("registry");
    std::fs::create_dir_all(&registry)
        .with_context(|| format!("creating {}", registry.display()))?;
    crate::cachelock::acquire_shared(
        &registry.join("chunks.inuse"),
        &registry.join("chunks.used"),
    )
}

/// Reclaim what the Windows cache rooted at `root` has not used for `idle`: entries nobody
/// references ([`reference`]), never one a kept entry stands on, then the chunks no pulled
/// layer still reads, what a process that is gone left unpublished, and the sidecars of
/// references to entries never made. Entries made before this sweep existed are dated now.
/// Best effort.
pub(crate) fn gc(root: &Path, idle: std::time::Duration) {
    let now = std::time::SystemTime::now();
    let mut freed = 0usize;
    // First every idle entry nobody holds is locked, and stays locked to the end: a build
    // waits for the sweep before it references one, then finds it kept or gone. Every other
    // entry — held, used lately, or undated — keeps what it stands on.
    let mut candidates = Vec::new();
    let mut standing = Vec::new();
    let chained = chained_kinds(root).len();
    for (n, kind) in entry_dirs(root).into_iter().enumerate() {
        freed = freed.saturating_add(clear_dead_scratch(&kind, None, idle, now));
        let Ok(dir_entries) = std::fs::read_dir(&kind) else {
            continue;
        };
        for entry in dir_entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                // A reference to an entry that was never made (a layer that stayed in the
                // registry) leaves its sidecars alone: they go once idle.
                if let Some(key) = entry
                    .file_name()
                    .to_str()
                    .and_then(|n| n.strip_suffix(".used"))
                    && !kind.join(key).exists()
                {
                    let never = kind.join(key);
                    let (lock, used) = sidecars(&never);
                    crate::cachelock::try_reclaim(&lock, &used, idle, now, || {
                        // Looked at under the lock: an entry published since keeps its own.
                        if !never.exists() {
                            remove_sidecars(&lock, &used);
                        }
                    });
                }
                continue;
            }
            // Keys only: an unpublished `<key>.tmp-<pid>` is `clear_dead_scratch`'s.
            if entry.file_name().as_encoded_bytes().contains(&b'.') {
                continue;
            }
            let (lock, used) = sidecars(&dir);
            if !used.exists() {
                // Undated: dated now, and kept this time with what it stands on.
                crate::cachelock::stamp(&lock, &used);
            } else if let Some(held) = crate::cachelock::try_exclusive(&lock)
                // Judged under the lock: a user dates its entry before it lets go.
                && crate::cachelock::is_idle(&used, idle, now)
            {
                candidates.push((dir, held));
                continue;
            }
            if n < chained {
                standing.push(dir);
            }
        }
    }
    let mut kept = std::collections::HashSet::new();
    for dir in &standing {
        let disk = layer_disk(dir);
        let mut chain = Vec::new();
        match walk_chain(root, &disk, &mut chain, |_| Ok(())) {
            Ok(()) => {}
            // What it stands on is gone already: nothing under it is left to keep.
            Err(e) if crate::cachelock::is_not_found(&e) => {
                // An entry a concurrent sweep took is no news.
                if dir.exists() {
                    eprintln!(
                        "virtkit: warning: Windows cache: {}: {e:#}; its chain ends there",
                        dir.display()
                    );
                }
            }
            // A disk whose chain cannot be read keeps the whole cache: what it stands on is
            // unknown.
            Err(e) => {
                eprintln!(
                    "virtkit: warning: Windows cache: not swept: {}: {e:#}",
                    dir.display()
                );
                return;
            }
        }
        kept.extend(chain);
    }
    for (dir, held) in candidates {
        if kept.contains(&dir) {
            continue;
        }
        match remove_entry(&dir) {
            Ok(()) => freed = freed.saturating_add(1),
            Err(e) => eprintln!("virtkit: warning: Windows cache: {e:#}"),
        }
        // Released only once the entry and its sidecars are gone.
        drop(held);
    }
    let chunks = sweep_chunks(root, idle, now);
    if freed > 0 || chunks > 0 {
        eprintln!(
            "virtkit: Windows cache: reclaimed {freed} entries and {chunks} chunks idle for {}s",
            idle.as_secs()
        );
    }
}

/// Remove `dir` and its sidecars under the caller's exclusive lock. Rename it first so no user
/// sees a partial removal. A waiter acquires the unlinked lock file, retries through
/// [`crate::cachelock::acquire_shared`], then finds the entry gone.
fn remove_entry(dir: &Path) -> Result<()> {
    let mut name = dir
        .file_name()
        .context("a cache entry with no name")?
        .to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    let doomed = dir.with_file_name(name);
    std::fs::rename(dir, &doomed)
        .with_context(|| format!("renaming {} out of the way", dir.display()))?;
    let (lock, used) = sidecars(dir);
    remove_sidecars(&lock, &used);
    // A part left behind is a dead process's scratch once this one is gone.
    std::fs::remove_dir_all(&doomed).with_context(|| format!("removing {}", doomed.display()))
}

/// Remove the entry `dir` now, as [`gc`] would, unless someone references it: for a build that
/// made it and found it unusable. Returns whether it is gone; one still referenced is left for
/// [`gc`] to take once idle.
pub(crate) fn discard(dir: &Path) -> Result<bool> {
    let (lock, used) = sidecars(dir);
    let Some(held) = crate::cachelock::try_exclusive(&lock) else {
        return Ok(false);
    };
    if dir.exists() {
        remove_entry(dir)?;
    } else {
        // A sweep took it meanwhile: the lock just taken is a sidecar of nothing.
        remove_sidecars(&lock, &used);
    }
    // Released only once the entry and its sidecars are gone.
    drop(held);
    Ok(true)
}

/// Remove an entry's sidecars, `lock` last; one already gone is no matter. Best effort, with a
/// warning: a sidecar left behind costs an inode, and goes with the next sweep.
fn remove_sidecars(lock: &Path, used: &Path) {
    for path in [used, lock] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "virtkit: warning: Windows cache: removing {}: {e}",
                path.display()
            ),
        }
    }
}

/// Remove unpublished `<key>.tmp-<pid>` directories in `kind` whose process is gone and which
/// have been untouched for `idle`; restrict to `key` when given. The idle window preserves
/// failed attempts' logs for readers of their errors. Return the removal count; failures stay
/// for the next sweep.
pub(crate) fn clear_dead_scratch(
    kind: &Path,
    key: Option<&str>,
    idle: std::time::Duration,
    now: std::time::SystemTime,
) -> usize {
    let mut removed = 0usize;
    for entry in std::fs::read_dir(kind).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some((of, pid)) = name.to_str().and_then(|n| n.rsplit_once(".tmp-")) else {
            continue;
        };
        // A pid is positive: `kill` reads 0 and the negatives as process groups.
        let Some(pid) = pid
            .parse::<i32>()
            .ok()
            .filter(|&p| p > 0)
            .and_then(|p| u32::try_from(p).ok())
        else {
            continue;
        };
        if key.is_some_and(|k| k != of) || crate::spawn::pid_alive(pid) {
            continue;
        }
        let quiet = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| now.duration_since(t).unwrap_or_default() >= idle);
        let dir = entry.file_type().is_ok_and(|t| t.is_dir());
        if quiet && dir && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed = removed.saturating_add(1);
        }
    }
    removed
}

/// Remove the chunks under `root`'s chunk cache that no pulled layer reads — published, or a
/// pull's still staged — and nothing used for `idle`, with the staging files and directories
/// of pulls whose process is gone. Only while no pull holds the store ([`hold_chunks`]): one
/// gathers its chunks before it writes the view that reads them. Returns how many chunks went.
fn sweep_chunks(root: &Path, idle: std::time::Duration, now: std::time::SystemTime) -> usize {
    let registry = root.join("registry");
    let Some(_store) = crate::cachelock::try_exclusive(&registry.join("chunks.inuse")) else {
        return 0;
    };
    clear_dead_scratch(&registry, None, idle, now);
    // A view moves from a pull's staging to its entry: staging first, so it is seen in either.
    let staged = std::fs::read_dir(&registry)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n != "chunks"));
    let published = entry_dirs(root)
        .into_iter()
        .flat_map(|kind| std::fs::read_dir(kind).into_iter().flatten().flatten())
        .map(|e| e.path());
    let mut live = std::collections::HashSet::new();
    for dir in staged.chain(published).filter(|p| p.is_dir()) {
        match crate::qcow2::VkRoImg::open(&dir.join(PULLED_DISK)) {
            Ok(view) => live.extend(view.digests().map(|d| crate::build::hex(d))),
            Err(e) if crate::cachelock::is_not_found(&e) => {}
            // A view that cannot be read reads chunks nobody can name: keep them all.
            Err(e) => {
                eprintln!(
                    "virtkit: warning: Windows cache: chunks not swept: {}: {e:#}",
                    dir.join(PULLED_DISK).display()
                );
                return 0;
            }
        }
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(registry.join("chunks"))
        .into_iter()
        .flatten()
        .flatten()
    {
        // A chunk is named by its hex digest; anything else is not one.
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.ends_with(".tmp") {
            if crate::image::staging_writer_is_gone(&name)
                && std::fs::remove_file(entry.path()).is_ok()
            {
                removed = removed.saturating_add(1);
            }
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| now.duration_since(t).unwrap_or_default() >= idle);
        if old && !live.contains(&name) && std::fs::remove_file(entry.path()).is_ok() {
            removed = removed.saturating_add(1);
        }
    }
    removed
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

    /// Round-trip layers through a local store, preserving disk contents and each password.
    /// Diff pushes over both pushed and pulled parents restore the whole disk.
    #[test]
    fn layers_round_trip_through_a_local_store() {
        if !have("qemu-io") {
            eprintln!("skipping: qemu-io not available");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("vk-wincache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let rg = Registry::for_share(
            tmp.join("store").display().to_string(),
            false,
            None,
            String::new(),
            None,
            None,
            None,
        );
        round_trip(&rg, &tmp, false);
    }

    /// [`layers_round_trip_through_a_local_store`] through a fleet's registry server.
    /// Pulled chunks land in the cache shared by all Windows layers.
    #[test]
    fn layers_round_trip_through_a_registry_server() {
        if !have("qemu-io") {
            eprintln!("skipping: qemu-io not available");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("vk-wincache-http-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let rg = crate::registry::tests::served_store(&tmp.join("store"));
        round_trip(&rg, &tmp, true);
    }

    fn round_trip(rg: &Registry, tmp: &Path, over_http: bool) {
        let host_a = tmp.join("a");
        let host_b = tmp.join("b");
        for dir in [&host_a, &host_b] {
            std::fs::create_dir_all(dir.join("layers")).unwrap();
        }

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
            rg,
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
            rg,
            &key(2),
            &step,
            Some(&base_dir),
            serde_json::json!({"password": "pa"}),
        )
        .unwrap();

        // Host B pulls the step alone, and gets every byte of it.
        let pulled = host_b.join("layers").join(key(2));
        std::fs::create_dir_all(&pulled).unwrap();
        let meta = pull(rg, &host_b, &key(2), None, &pulled).unwrap().unwrap();
        assert_eq!(meta["password"], "pa");
        assert_eq!(password(&pulled).unwrap().as_deref(), Some("pa"));
        assert!(layer_disk(&pulled).ends_with(PULLED_DISK));
        assert_eq!(contents(&layer_disk(&pulled), tmp), contents(&step, tmp));
        if over_http {
            let chunks = host_b.join("registry").join("chunks");
            assert!(
                std::fs::read_dir(&chunks).is_ok_and(|mut d| d.next().is_some()),
                "no chunk in {}",
                chunks.display()
            );
        }

        // Host B makes a step over the pulled one, with a password of its own; its diff push
        // reuses the pulled layer's chunks and still reads back whole.
        let next_dir = host_b.join("layers").join(key(3));
        std::fs::create_dir_all(&next_dir).unwrap();
        let next = next_dir.join(BUILT_DISK);
        crate::qcow2::create_overlay(&next, &layer_disk(&pulled)).unwrap();
        write(&next, 0x44, 2 << 20, 128 << 10);
        push(
            rg,
            &key(3),
            &next,
            Some(&pulled),
            serde_json::json!({"password": "pb"}),
        )
        .unwrap();
        let again = tmp.join("c").join(key(3));
        std::fs::create_dir_all(&again).unwrap();
        let meta = pull(rg, &tmp.join("c"), &key(3), None, &again)
            .unwrap()
            .unwrap();
        assert_eq!(meta["password"], "pb");
        assert_eq!(contents(&layer_disk(&again), tmp), contents(&next, tmp));

        // A layer the registry does not have.
        let none = tmp.join("none");
        std::fs::create_dir_all(&none).unwrap();
        assert!(pull(rg, &host_b, &key(9), None, &none).unwrap().is_none());
        let _ = std::fs::remove_dir_all(tmp);
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
        let view = crate::qcow2::VkRoImg::open(&pulled.join(PULLED_DISK)).unwrap();
        assert_eq!(view.digests().collect::<Vec<_>>(), [&[0x07; 32]]);

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
        let refs = Refs::default();
        refs.reference_chain(&root, &bundle.join("disk.qcow2"))
            .unwrap();
        assert!(refs.holds(&step) && refs.holds(&install));
        assert_eq!(refs.into_guards().len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sweep never takes what a kept layer stands on, however long ago it was used itself;
    /// it takes what a process that is gone left unpublished once that is idle too, and keeps
    /// the chunks a pull still in progress staged a view over.
    #[test]
    fn a_sweep_keeps_the_chain_of_a_kept_layer() {
        let root = std::env::temp_dir().join(format!("vk-wincache-kept-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let install = root.join("winiso/install").join(key(1));
        let step = root.join("layers").join(key(2));
        for dir in [&install, &step] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let raw = install.join("disk.raw");
        std::fs::write(&raw, vec![0u8; 1 << 20]).unwrap();
        crate::qcow2::create_overlay(&install.join(BUILT_DISK), &raw).unwrap();
        crate::qcow2::create_overlay(&step.join(BUILT_DISK), &install.join(BUILT_DISK)).unwrap();
        // Dated: the install long ago, the step just now.
        drop(reference(&install).unwrap());
        let (_, install_used) = sidecars(&install);
        std::fs::File::options()
            .write(true)
            .open(&install_used)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
        drop(reference(&step).unwrap());

        // What a dead process left: an unpublished entry, and a pull's staging with its view.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let unpublished = root.join("layers").join(format!("{}.tmp-{dead}", key(3)));
        std::fs::create_dir_all(&unpublished).unwrap();
        let chunks = root.join("registry/chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        std::fs::write(chunks.join(key(9)), b"chunk").unwrap();
        let staged = root
            .join("registry")
            .join(format!("{}.tmp-{}", key(4), std::process::id()));
        crate::registry::write_vk_ro_img(
            &staged.join(PULLED_DISK),
            4096,
            crate::registry::VK_RO_IMG_LAYOUT_FLAT,
            &chunks,
            &[crate::registry::LazyChunk {
                offset: 0,
                length: 4096,
                codec: crate::registry::VK_RO_IMG_CODEC_RAW,
                digest: [0x09; 32],
            }],
        )
        .unwrap();

        gc(&root, std::time::Duration::from_secs(60));
        assert!(install.exists(), "a kept layer's install stays");
        assert!(step.exists());
        assert!(
            unpublished.exists(),
            "a dead process's recent attempt keeps its logs"
        );
        std::fs::File::open(&unpublished)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
        gc(&root, std::time::Duration::from_secs(60));
        assert!(
            !unpublished.exists(),
            "a dead process's idle unpublished entry goes"
        );
        assert!(staged.exists(), "a live pull's staging stays");
        std::fs::File::options()
            .write(true)
            .open(chunks.join(key(9)))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
        gc(&root, std::time::Duration::from_secs(60));
        assert!(chunks.join(key(9)).exists(), "a staged view's chunk stays");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An image that cannot be read is an error, not the end of its chain: what it stands on
    /// would otherwise go unreferenced.
    #[test]
    fn an_unreadable_disk_breaks_its_chain() {
        let root = std::env::temp_dir().join(format!("vk-wincache-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let step = root.join("layers").join(key(1));
        std::fs::create_dir_all(&step).unwrap();
        assert!(
            Refs::default()
                .reference_chain(&root, &step.join(BUILT_DISK))
                .is_err()
        );
        std::fs::write(step.join("raw.img"), vec![0u8; 512]).unwrap();
        let refs = Refs::default();
        refs.reference_chain(&root, &step.join("raw.img")).unwrap();
        assert_eq!(refs.into_guards().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An entry a sweep finds undated keeps what it stands on that sweep too; a reference to an
    /// entry never made leaves sidecars that go once idle.
    #[test]
    fn a_sweep_keeps_under_an_undated_layer_and_drops_orphan_sidecars() {
        let root = std::env::temp_dir().join(format!("vk-wincache-undated-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let install = root.join("winiso/install").join(key(1));
        let step = root.join("layers").join(key(2));
        for dir in [&install, &step] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let raw = install.join("disk.raw");
        std::fs::write(&raw, vec![0u8; 1 << 20]).unwrap();
        crate::qcow2::create_overlay(&install.join(BUILT_DISK), &raw).unwrap();
        crate::qcow2::create_overlay(&step.join(BUILT_DISK), &install.join(BUILT_DISK)).unwrap();
        // The install dated long ago; the step, from before sweeps existed, not at all.
        drop(reference(&install).unwrap());
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let set_old = |path: &Path| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        };
        set_old(&sidecars(&install).1);
        // A layer referenced but never made.
        let never = root.join("layers").join(key(3));
        drop(reference(&never).unwrap());
        set_old(&sidecars(&never).1);

        let (lock, used) = sidecars(&never);
        assert!(
            crate::cachelock::reclaimed_eventually(|| {
                gc(&root, std::time::Duration::from_secs(60));
                !used.exists() && !lock.exists()
            }),
            "orphan sidecars go once idle"
        );
        assert!(install.exists(), "the install under an undated layer stays");
        assert!(
            step.exists() && sidecars(&step).1.exists(),
            "the undated layer is dated"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
    /// Date the `.used` marker of the entry `dir` an hour back.
    fn age(dir: &Path) {
        set_old(&sidecars(dir).1);
    }

    /// Set the mtime of `path` an hour back.
    fn set_old(path: &Path) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
    }

    /// An install, and a layer over it, both as a build makes them; both dated an hour back.
    fn install_and_step(root: &Path) -> (PathBuf, PathBuf) {
        let install = root.join("winiso/install").join(key(1));
        let step = root.join("layers").join(key(2));
        for dir in [&install, &step] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let raw = install.join("disk.raw");
        std::fs::write(&raw, vec![0u8; 1 << 20]).unwrap();
        crate::qcow2::create_overlay(&install.join(BUILT_DISK), &raw).unwrap();
        crate::qcow2::create_overlay(&step.join(BUILT_DISK), &install.join(BUILT_DISK)).unwrap();
        for dir in [&install, &step] {
            drop(reference(dir).unwrap());
            age(dir);
        }
        (install, step)
    }

    /// A layer a build or job holds keeps what it stands on, however idle and unheld that is.
    #[test]
    fn a_held_layer_keeps_its_idle_install() {
        let root = std::env::temp_dir().join(format!("vk-wincache-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (install, step) = install_and_step(&root);
        let held = reference(&step).unwrap();
        age(&step);
        gc(&root, std::time::Duration::from_secs(60));
        assert!(install.exists() && step.exists());
        drop(held);
        age(&step);
        assert!(crate::cachelock::reclaimed_eventually(|| {
            gc(&root, std::time::Duration::from_secs(60));
            !install.exists() && !step.exists()
        }));
        let (lock, used) = sidecars(&install);
        assert!(
            !lock.exists() && !used.exists(),
            "a reclaimed entry's sidecars go"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sweep cannot lock an entry a reference holds; and an entry it has locked, a build
    /// that references it meanwhile waits for, then finds gone and says so.
    #[test]
    fn a_reference_waits_for_a_sweep_and_finds_its_entry_gone() {
        let root = std::env::temp_dir().join(format!("vk-wincache-wait-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (install, step) = install_and_step(&root);
        let (lock, _) = sidecars(&step);
        let held = reference(&step).unwrap();
        assert!(crate::cachelock::try_exclusive(&lock).is_none());
        drop(held);
        let swept = loop {
            if let Some(locked) = crate::cachelock::try_exclusive(&lock) {
                break locked;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let (from, disk) = (root.clone(), step.join(BUILT_DISK));
        let build = std::thread::spawn(move || {
            let refs = Refs::default();
            refs.reference_chain(&from, &disk)
                .map(|()| refs.into_guards().len())
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!build.is_finished(), "a reference waits for the sweep");
        remove_entry(&step).unwrap();
        drop(swept);
        let err = format!("{:#}", build.join().unwrap().unwrap_err());
        assert!(err.contains("gone from the Windows build cache"), "{err}");
        assert!(install.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A kept layer whose backing is gone ends its chain there: the sweep goes on with the rest.
    #[test]
    fn a_missing_backing_ends_a_chain_without_stopping_the_sweep() {
        let root = std::env::temp_dir().join(format!("vk-wincache-gone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (install, step) = install_and_step(&root);
        // Its install vanished behind the cache's back; the step is used just now.
        std::fs::remove_dir_all(&install).unwrap();
        drop(reference(&step).unwrap());
        let other = root.join("winiso/media").join(key(3));
        std::fs::create_dir_all(&other).unwrap();
        drop(reference(&other).unwrap());
        age(&other);
        assert!(crate::cachelock::reclaimed_eventually(|| {
            gc(&root, std::time::Duration::from_secs(60));
            !other.exists()
        }));
        assert!(step.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The chunk store is swept only while no pull holds it, and then only of chunks idle and
    /// read by no view.
    #[test]
    fn a_busy_chunk_store_is_not_swept() {
        let root = std::env::temp_dir().join(format!("vk-wincache-busy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let chunks = root.join("registry/chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        let (old, new) = (chunks.join(key(1)), chunks.join(key(2)));
        for c in [&old, &new] {
            std::fs::write(c, b"chunk").unwrap();
        }
        set_old(&old);
        let idle = std::time::Duration::from_secs(60);
        let pull = hold_chunks(&root).unwrap();
        assert_eq!(sweep_chunks(&root, idle, std::time::SystemTime::now()), 0);
        assert!(old.exists());
        drop(pull);
        assert!(crate::cachelock::reclaimed_eventually(|| {
            sweep_chunks(&root, idle, std::time::SystemTime::now());
            !old.exists()
        }));
        assert!(new.exists(), "a chunk written lately stays");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A backing chain that loops is an error, not a hang.
    #[test]
    fn a_looping_chain_is_an_error() {
        let root = std::env::temp_dir().join(format!("vk-wincache-loop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (install, step) = install_and_step(&root);
        // The install's disk swapped for one backed by the step over it.
        let looped = install.join("looped.qcow2");
        crate::qcow2::create_overlay(&looped, &step.join(BUILT_DISK)).unwrap();
        std::fs::rename(&looped, install.join(BUILT_DISK)).unwrap();
        let err = Refs::default()
            .reference_chain(&root, &step.join(BUILT_DISK))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("backing chain loops"),
            "{err:#}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A build discards an entry it made only once its own reference is gone and nobody else
    /// holds it, taking its sidecars with it; one another build holds stays.
    #[test]
    fn a_discarded_entry_goes_unless_referenced() {
        let root = std::env::temp_dir().join(format!("vk-wincache-discard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (install, _) = install_and_step(&root);
        let refs = Refs::default();
        refs.reference(&install).unwrap();
        let other = reference(&install).unwrap();
        refs.release(&install);
        assert!(!refs.holds(&install));
        assert!(!discard(&install).unwrap());
        assert!(install.exists(), "an entry another build holds stays");
        drop(other);
        assert!(crate::cachelock::reclaimed_eventually(
            || discard(&install).unwrap()
        ));
        let (lock, used) = sidecars(&install);
        assert!(!install.exists() && !lock.exists() && !used.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
