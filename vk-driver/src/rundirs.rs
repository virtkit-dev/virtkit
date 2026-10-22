//! Track root images built by `vk run --state-dir` for collection once their directories
//! become idle, wherever they are. Each entry under `<data dir>/runs/` records a directory
//! and its built files by identity. `vk gc` removes only files that still match the record.

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a run's build writes into its state dir and every later run writes again: the root
/// image, booted read-only under an overlay, and its config sidecar.
const ARTIFACTS: &[&str] = &["root.qcow2", "root.qcow2.json"];

/// What a removal renames an artifact to under the dir's lock, to unlink once it is let go: a
/// run starting on the dir waits for a rename, not for the unlink of a large image.
const TRASH: &str = ".virtkit-trash-";

/// A ledger entry: a state dir a run built into, the directory it was, and what it built.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Entry {
    state_dir: PathBuf,
    dev: u64,
    ino: u64,
    #[serde(default)]
    artifacts: Vec<Artifact>,
    /// Artifacts a removal renamed away and has yet to unlink, as they were: what the next
    /// pass removes under the trash name.
    #[serde(default)]
    leftovers: Vec<Artifact>,
}

/// A file a run built into its state dir, as it was then: what a removal checks it still is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Artifact {
    name: String,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Artifact {
    fn of(name: &str, st: &libc::stat) -> Artifact {
        Artifact {
            name: name.to_string(),
            dev: st.st_dev,
            ino: st.st_ino,
            size: u64::try_from(st.st_size).unwrap_or(0),
            mtime: st.st_mtime,
            mtime_nsec: st.st_mtime_nsec,
        }
    }

    /// Whether `st` is the file this records: the same inode, untouched since.
    fn is(&self, st: &libc::stat) -> bool {
        Artifact::of(&self.name, st) == *self
    }
}

fn ledger_dir() -> Result<PathBuf> {
    Ok(crate::run::default_data_base()?.join("runs"))
}

/// Note that a run built its root image into the pinned `state_dir`, as it is now. A dir under
/// the `vk dev` state base is not noted: `vk gc` reclaims an environment's images as a whole.
pub(crate) fn record(state_dir: &Path) -> Result<()> {
    if let Ok(base) = crate::dev::plan::dev_state_base()
        && let (Ok(base), Ok(dir)) = (
            std::fs::canonicalize(base),
            std::fs::canonicalize(state_dir),
        )
        && dir.starts_with(base)
    {
        return Ok(());
    }
    record_in(&ledger_dir()?, state_dir)
}

fn record_in(ledger: &Path, state_dir: &Path) -> Result<()> {
    let state_dir = std::fs::canonicalize(state_dir)
        .with_context(|| format!("resolving {}", state_dir.display()))?;
    let dir = open_dir(&state_dir)?;
    let meta = dir
        .metadata()
        .with_context(|| format!("inspecting {}", state_dir.display()))?;
    let artifacts = ARTIFACTS
        .iter()
        .filter_map(|name| {
            let st = stat_in(&dir, name)?;
            (st.st_mode & libc::S_IFMT == libc::S_IFREG).then(|| Artifact::of(name, &st))
        })
        .collect();
    // A leftover a removal cut short is still to go, whatever was built since.
    let note = note_path(ledger, &state_dir);
    let leftovers = std::fs::read(&note)
        .ok()
        .and_then(|b| serde_json::from_slice::<Entry>(&b).ok())
        .filter(|e| (e.dev, e.ino) == (meta.dev(), meta.ino()))
        .map(|e| e.leftovers)
        .unwrap_or_default();
    let entry = Entry {
        dev: meta.dev(),
        ino: meta.ino(),
        state_dir,
        artifacts,
        leftovers,
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(ledger)
        .with_context(|| format!("creating {}", ledger.display()))?;
    save(&note, &entry)
}

fn save(note: &Path, entry: &Entry) -> Result<()> {
    vk_fs::write_atomic_unsynced(note, &serde_json::to_vec(entry)?, 0o600)
}

fn note_path(ledger: &Path, state_dir: &Path) -> PathBuf {
    let digest = Sha256::digest(state_dir.as_os_str().as_bytes());
    let name: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    ledger.join(format!("{name}.json"))
}

fn open_dir(dir: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .with_context(|| format!("opening {}", dir.display()))
}

/// The `stat` of `name` in the open `dir`, unfollowed.
fn stat_in(dir: &std::fs::File, name: &str) -> Option<libc::stat> {
    let c_name = CString::new(name).ok()?;
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is open for the borrow, the name NUL-terminated, `st` writable.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    (rc == 0).then_some(st)
}

/// The state dirs noted, for a pass to read the space on their filesystems before it starts.
pub(crate) fn noted_dirs() -> Vec<PathBuf> {
    let Ok(ledger) = ledger_dir() else {
        return Vec::new();
    };
    notes(&ledger)
        .into_iter()
        .map(|(_, e)| e.state_dir)
        .collect()
}

fn notes(ledger: &Path) -> Vec<(PathBuf, Entry)> {
    let Ok(entries) = std::fs::read_dir(ledger) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|note| {
            let path = note.path();
            let entry = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Entry>(&b).ok())?;
            Some((path, entry))
        })
        .collect()
}

/// What [`collect`] removed, and what it left and why.
#[derive(Debug, Default)]
pub(crate) struct Collected {
    /// State dirs it removed a root image from, and the space each freed.
    pub(crate) dirs: Vec<(PathBuf, u64)>,
    pub(crate) kept: Vec<String>,
}

/// Remove the root images of the noted state dirs no run has held for `idle`, by
/// [`crate::run::last_active`] read under the dir's lock. A dir is left while a VM registered
/// on it runs (read before taking its lock, which would make the registry think the run
/// alive), while anyone holds its lock, and when it is no longer the directory noted; a file
/// is left unless it is still the one the run built, and only those [`ARTIFACTS`] go. With
/// `only_on`, only dirs on that device. A note whose dir is gone or replaced is dropped. With
/// `dry_run`, what it would remove.
pub(crate) fn collect(idle: Duration, only_on: Option<u64>, dry_run: bool) -> Collected {
    let running: Vec<PathBuf> = crate::vms::running()
        .iter()
        .map(|vm| crate::vms::canonical(&vm.state_dir))
        .collect();
    match ledger_dir() {
        Ok(ledger) => collect_in(&ledger, &running, idle, only_on, SystemTime::now(), dry_run),
        Err(_) => Collected::default(),
    }
}

fn collect_in(
    ledger: &Path,
    running: &[PathBuf],
    idle: Duration,
    only_on: Option<u64>,
    now: SystemTime,
    dry_run: bool,
) -> Collected {
    let mut done = Collected::default();
    for (note, mut entry) in notes(ledger) {
        let dir = entry.state_dir.clone();
        let dir = &dir;
        let meta = match std::fs::symlink_metadata(dir) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !dry_run {
                    let _ = std::fs::remove_file(&note);
                }
                continue;
            }
            Err(_) => continue,
        };
        // Another directory, or something else, now has the path: not the dir the run built
        // into, so nothing in it is this note's to remove, and the note is dropped.
        if !meta.is_dir() || (meta.dev(), meta.ino()) != (entry.dev, entry.ino) {
            if !dry_run {
                let _ = std::fs::remove_file(&note);
            }
            continue;
        }
        let quiet = || {
            crate::run::last_active(dir)
                .is_some_and(|t| now.duration_since(t).unwrap_or_default() >= idle)
        };
        // Looked at unlocked first, so a dir in use is never locked: only one that looks idle
        // is, and read again then.
        if only_on.is_some_and(|dev| dev != meta.dev())
            || running.iter().any(|r| r == dir)
            || !quiet()
        {
            continue;
        }
        let Ok(held) = open_dir(dir) else {
            continue;
        };
        let same = held
            .metadata()
            .is_ok_and(|m| (m.dev(), m.ino()) == (entry.dev, entry.ino));
        // SAFETY: the fd is owned by `held`, open across the call; LOCK_NB never waits.
        if !same || unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        if !quiet() {
            continue;
        }
        match remove_artifacts(&held, &mut entry, &note, dry_run) {
            Ok((0, _)) => {}
            Ok((_, bytes)) => done.dirs.push((dir.clone(), bytes)),
            Err(e) => done.kept.push(format!("{}: {e:#}", dir.display())),
        }
    }
    done
}

/// Remove from the open, locked `dir` each of `entry`'s artifacts that is still the file
/// recorded — a plain file of this user's — and each leftover an earlier removal renamed away:
/// renamed under the lock, without replacing anything, noted in `note` as a leftover, and
/// unlinked once the lock is let go, then struck off. The number removed and the space they
/// held. With `dry_run`, what they hold.
fn remove_artifacts(
    dir: &std::fs::File,
    entry: &mut Entry,
    note: &Path,
    dry_run: bool,
) -> Result<(u64, u64)> {
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let ours = |name: &str, a: &Artifact| {
        stat_in(dir, name)
            .filter(|st| st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_uid == me && a.is(st))
    };
    let (mut files, mut bytes) = (0u64, 0u64);
    let mut count = |st: &libc::stat| {
        files += 1;
        if st.st_nlink <= 1 {
            let held = u64::try_from(st.st_blocks).unwrap_or(0).saturating_mul(512);
            bytes = bytes.saturating_add(held);
        }
    };
    // What an earlier removal left renamed away, while it is still that file.
    entry
        .leftovers
        .retain(|a| ours(&format!("{TRASH}{}", a.name), a).is_some());
    for a in &entry.leftovers {
        if let Some(st) = ours(&format!("{TRASH}{}", a.name), a) {
            count(&st);
        }
    }
    let _holder = (!dry_run)
        .then(|| crate::run::GcHolder::mark(dir))
        .flatten();
    let mut moved: Vec<String> = Vec::new();
    for a in &entry.artifacts {
        if !ARTIFACTS.contains(&a.name.as_str()) {
            continue;
        }
        let Some(st) = ours(&a.name, a) else {
            continue;
        };
        let away = format!("{TRASH}{}", a.name);
        if dry_run {
            count(&st);
            continue;
        }
        // Something else under the trash name — not an image of ours — is left, and so is
        // this artifact, for now.
        if stat_in(dir, &away).is_some() {
            continue;
        }
        // Noted before it is moved, so a pass cut short leaves it for the next.
        let mut noted = entry.leftovers.clone();
        noted.push(a.clone());
        let staged = Entry {
            state_dir: entry.state_dir.clone(),
            dev: entry.dev,
            ino: entry.ino,
            artifacts: entry.artifacts.clone(),
            leftovers: noted,
        };
        save(note, &staged)?;
        let (from, to) = (CString::new(a.name.as_str())?, CString::new(away.as_str())?);
        // SAFETY: the fd is open for the borrow and both names NUL-terminated; RENAME_NOREPLACE
        // refuses to replace what may have appeared under the trash name meanwhile.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                from.as_ptr(),
                dir.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            save(note, entry)?;
            if e.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(e).with_context(|| format!("removing {}", a.name));
        }
        count(&st);
        moved.push(a.name.clone());
        entry.leftovers = staged.leftovers;
    }
    if dry_run {
        return Ok((files, bytes));
    }
    entry.artifacts.retain(|a| !moved.contains(&a.name));
    drop(_holder);
    // SAFETY: as above; letting the lock go lets a run start while the unlinks go on.
    unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_UN) };
    let mut left = Vec::new();
    for a in std::mem::take(&mut entry.leftovers) {
        let name = CString::new(format!("{TRASH}{}", a.name))?;
        // SAFETY: as above.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                left.push(a);
            }
        }
    }
    entry.leftovers = left;
    save(note, entry)?;
    Ok((files, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A noted dir unused for the window loses its root image and keeps everything else; one
    /// a VM runs on, one whose lock is held, one used lately, one never dated, one replaced, and
    /// one on another device keep theirs; a note whose dir is gone, or replaced, is dropped.
    #[test]
    fn only_the_root_image_of_an_idle_noted_dir_goes() {
        let base = std::env::temp_dir().join(format!("vk-rundirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let ledger = base.join("runs");
        let day = Duration::from_secs(86_400);
        let now = SystemTime::now();
        let state = |name: &str, active: Option<SystemTime>| {
            let dir = base.join(name);
            std::fs::create_dir_all(dir.join("svc-db")).unwrap();
            std::fs::write(dir.join("root.qcow2"), vec![1u8; 16 * 1024]).unwrap();
            std::fs::write(dir.join("root.qcow2.json"), b"{}").unwrap();
            std::fs::write(dir.join("id_ed25519"), b"key").unwrap();
            std::fs::write(dir.join("svc-db/root.qcow2"), b"service").unwrap();
            if let Some(t) = active {
                let stamp = dir.join(crate::run::ACTIVE_STAMP);
                std::fs::write(&stamp, b"").unwrap();
                std::fs::File::open(&stamp)
                    .unwrap()
                    .set_modified(t)
                    .unwrap();
            }
            record_in(&ledger, &dir).unwrap();
            std::fs::canonicalize(dir).unwrap()
        };
        let idle = state("idle", Some(now - day * 20));
        let running = state("running", Some(now - day * 20));
        let held = state("held", Some(now - day * 20));
        let recent = state("recent", Some(now - day));
        let undated = state("undated", None);
        let gone = state("gone", Some(now - day * 20));
        std::fs::remove_dir_all(&gone).unwrap();
        let replaced = state("replaced", Some(now - day * 20));
        std::fs::rename(&replaced, base.join("moved")).unwrap();
        std::fs::create_dir_all(&replaced).unwrap();
        std::fs::write(replaced.join("root.qcow2"), b"someone else's").unwrap();
        let lock = std::fs::File::open(&held).unwrap();
        // SAFETY: the fd is owned by `lock`, open for the test.
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let notes = || std::fs::read_dir(&ledger).unwrap().count();
        assert_eq!(notes(), 7);
        let running = std::slice::from_ref(&running);

        let elsewhere = collect_in(&ledger, running, day * 14, Some(u64::MAX), now, true);
        assert!(elsewhere.dirs.is_empty(), "nothing on another device");

        let dry = collect_in(&ledger, running, day * 14, None, now, true);
        assert_eq!(dry.dirs.len(), 1);
        assert!(dry.dirs[0].1 >= 16 * 1024, "{:?}", dry.dirs);
        assert!(
            idle.join("root.qcow2").exists(),
            "a dry run removes nothing"
        );
        assert_eq!(notes(), 7, "a dry run drops no note");

        let real = collect_in(&ledger, running, day * 14, None, now, false);
        assert_eq!(real.dirs, dry.dirs);
        assert!(real.kept.is_empty(), "{:?}", real.kept);
        assert!(!idle.join("root.qcow2").exists());
        assert!(!idle.join("root.qcow2.json").exists());
        for kept in ["id_ed25519", "svc-db/root.qcow2", crate::run::ACTIVE_STAMP] {
            assert!(idle.join(kept).exists(), "{kept}");
        }
        assert!(
            std::fs::read_dir(&idle)
                .unwrap()
                .flatten()
                .all(|e| !e.file_name().as_bytes().starts_with(TRASH.as_bytes())),
            "nothing is left renamed away"
        );
        for dir in [&running[0], &held, &recent, &undated, &replaced] {
            assert!(dir.join("root.qcow2").exists(), "{}", dir.display());
        }
        assert_eq!(
            notes(),
            5,
            "the notes of the gone and the replaced dirs are dropped"
        );
        drop(lock);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Only the file the run built goes: one rewritten since and a symlink in its place are
    /// left; a hard-linked one goes, freeing nothing while its other name stands; one a
    /// removal cut short left renamed away goes with the next; and a file of someone else's
    /// under the trash name is neither replaced nor removed.
    #[test]
    fn only_the_file_the_run_built_goes() {
        let base = std::env::temp_dir().join(format!("vk-rundirs-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let ledger = base.join("runs");
        let old = SystemTime::now() - Duration::from_secs(86_400 * 20);
        let state = |name: &str| {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("root.qcow2"), vec![1u8; 16 * 1024]).unwrap();
            dir
        };
        let date = |dir: &Path| {
            let stamp = dir.join(crate::run::ACTIVE_STAMP);
            std::fs::write(&stamp, b"").unwrap();
            std::fs::File::open(&stamp)
                .unwrap()
                .set_modified(old)
                .unwrap();
        };
        let rewritten = state("rewritten");
        let linked = state("linked");
        let hard = state("hard");
        let cut = state("cut");
        let squatted = state("squatted");
        for dir in [&rewritten, &linked, &hard, &cut, &squatted] {
            record_in(&ledger, dir).unwrap();
            date(dir);
        }
        std::fs::write(squatted.join(format!("{TRASH}root.qcow2")), b"not ours").unwrap();
        std::fs::remove_file(rewritten.join("root.qcow2")).unwrap();
        std::fs::write(rewritten.join("root.qcow2"), b"another image").unwrap();
        let target = base.join("elsewhere");
        std::fs::write(&target, b"keep").unwrap();
        std::fs::remove_file(linked.join("root.qcow2")).unwrap();
        std::os::unix::fs::symlink(&target, linked.join("root.qcow2")).unwrap();
        std::fs::hard_link(hard.join("root.qcow2"), base.join("other-name")).unwrap();
        // What a pass cut short between its rename and its unlink leaves: the image under the
        // trash name, noted as a leftover.
        std::fs::rename(
            cut.join("root.qcow2"),
            cut.join(format!("{TRASH}root.qcow2")),
        )
        .unwrap();
        let note = note_path(&ledger, &std::fs::canonicalize(&cut).unwrap());
        let mut entry: Entry = serde_json::from_slice(&std::fs::read(&note).unwrap()).unwrap();
        entry.leftovers = std::mem::take(&mut entry.artifacts);
        save(&note, &entry).unwrap();

        let done = collect_in(
            &ledger,
            &[],
            Duration::from_secs(86_400 * 14),
            None,
            SystemTime::now(),
            false,
        );
        let freed: std::collections::HashMap<_, _> = done.dirs.into_iter().collect();
        assert!(rewritten.join("root.qcow2").exists(), "rewritten since");
        assert!(linked.join("root.qcow2").is_symlink() && target.exists());
        assert!(!hard.join("root.qcow2").exists() && base.join("other-name").exists());
        assert_eq!(freed[&std::fs::canonicalize(&hard).unwrap()], 0);
        assert!(!cut.join(format!("{TRASH}root.qcow2")).exists());
        assert!(freed[&std::fs::canonicalize(&cut).unwrap()] >= 16 * 1024);
        assert!(squatted.join("root.qcow2").exists());
        assert_eq!(
            std::fs::read(squatted.join(format!("{TRASH}root.qcow2"))).unwrap(),
            b"not ours"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
