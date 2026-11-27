//! What unfinished builds and killed tasks leave in vk's own state dirs, for `vk gc` to
//! remove: a build's scratch (`.build-*`) whose owner is gone, a staged export (`*.tmp`) no
//! build is writing, a boot's note (`.transition.<pid>`) to a parent that is gone, and a
//! task's throwaway state dir a killed `vk` left whole.
//!
//! A build or a task that ends — finished, failed, or stopped by a signal it can catch —
//! removes these itself. What is left is a `vk` killed outright: SIGKILL, the OOM killer, a
//! power cut. The steps an unfinished build finished are in the build cache, committed as
//! they finished, so nothing here is worth keeping.
//!
//! Only in a state dir nobody holds — a boot and a run hold its lock throughout — and only
//! what has not changed for [`GRACE`], so a task that made its dir and is about to lock it is
//! left to do so.

use std::path::Path;
use std::time::{Duration, SystemTime};

/// How long a leftover is left after it last changed.
const GRACE: Duration = Duration::from_secs(600);

/// What a pass removed, or would.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Collected {
    /// state dirs something was removed from, a throwaway one removed whole counting once
    pub dirs: u64,
    /// what it took on disk
    pub bytes: u64,
}

/// Remove the leftovers in every state dir under the dev and run state bases; with
/// `dry_run`, count them and leave them.
pub(crate) fn collect(dry_run: bool) -> Collected {
    let mut out = Collected::default();
    let bases = [crate::dev::plan::dev_state_base(), crate::names::run_base()];
    for base in bases.into_iter().flatten() {
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            // A state dir of vk's own, never a link leading elsewhere.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                collect_in(&entry.path(), dry_run, SystemTime::now(), &mut out);
            }
        }
    }
    out
}

/// [`collect`] on the one state dir `dir`, judging what has settled against `now`.
fn collect_in(dir: &Path, dry_run: bool, now: SystemTime, out: &mut Collected) {
    let Some(_lock) = crate::dev::list::try_lock_state_dir(dir) else {
        return; // a boot or a run holds it
    };
    let settled = |p: &Path| {
        std::fs::symlink_metadata(p)
            .and_then(|m| m.modified())
            .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age >= GRACE))
    };
    if dir.join(crate::dev::task::THROWAWAY_MARKER).is_file() {
        if settled(dir) {
            let bytes = crate::dev::storage::disk_usage(dir);
            if dry_run || std::fs::remove_dir_all(dir).is_ok() {
                if !dry_run
                    && let Ok(idx) = crate::names::Index::open()
                    && let Err(e) = idx.release(dir)
                {
                    eprintln!(
                        "vk: warning: forgetting the name of {}: {e:#}",
                        dir.display()
                    );
                }
                out.dirs += 1;
                out.bytes = out.bytes.saturating_add(bytes);
            }
        }
        return;
    }
    let mut bytes = 0u64;
    let mut found = false;
    // A compose service's images are built into its own directory, a level down.
    let services = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| e.file_name().to_string_lossy().starts_with("svc-"))
        .map(|e| e.path());
    let scopes: Vec<_> = std::iter::once(dir.to_path_buf()).chain(services).collect();
    for scope in &scopes {
        let Ok(entries) = std::fs::read_dir(scope) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let gone = if kind.is_dir() && name.starts_with(crate::build::SCRATCH_PREFIX) {
                // Held across the removal, so a build claiming it meanwhile waits it out.
                crate::build::claim_if_abandoned(&path).is_some_and(|_claim| {
                    let size = crate::dev::storage::disk_usage(&path);
                    let ok = dry_run || std::fs::remove_dir_all(&path).is_ok();
                    bytes = bytes.saturating_add(if ok { size } else { 0 });
                    ok
                })
            } else if kind.is_file() && (name.ends_with(".tmp") || dead_note(scope == dir, &name)) {
                settled(&path) && {
                    let size = crate::dev::storage::disk_usage(&path);
                    let ok = dry_run || std::fs::remove_file(&path).is_ok();
                    bytes = bytes.saturating_add(if ok { size } else { 0 });
                    ok
                }
            } else {
                false
            };
            found |= gone;
        }
    }
    if found {
        out.dirs += 1;
        out.bytes = out.bytes.saturating_add(bytes);
    }
}

/// Whether `name`, directly in a state dir (`top`), is a boot's note to a parent process that
/// is gone (`.transition.<pid>`): only that parent, while it lives, reads it.
fn dead_note(top: bool, name: &str) -> bool {
    let Some(pid) = top
        .then(|| name.strip_prefix(".transition."))
        .flatten()
        .and_then(|p| p.parse::<libc::pid_t>().ok())
        .filter(|&p| p > 0)
    else {
        return false;
    };
    // SAFETY: kill(2) with signal 0 only checks that the process exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    !alive
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-leftovers-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A pid no process has: past the kernel's maximum.
    const DEAD_PID: i32 = 4_194_305;

    #[test]
    fn a_state_dir_loses_only_what_an_unfinished_build_left() {
        let dir = scratch("state");
        for keep in ["root.qcow2", "root.qcow2.json", "dev.json", "id_ed25519"] {
            std::fs::write(dir.join(keep), b"x").unwrap();
        }
        std::fs::create_dir_all(dir.join("roots/home")).unwrap();
        std::fs::create_dir_all(dir.join(".build-1-0-x")).unwrap();
        std::fs::write(dir.join(".build-1-0-x/stage.qcow2"), vec![1u8; 8192]).unwrap();
        std::fs::write(dir.join("root.qcow2.tmp"), vec![1u8; 8192]).unwrap();
        std::fs::write(dir.join(format!(".transition.{DEAD_PID}")), b"booted 1").unwrap();
        let own = format!(".transition.{}", std::process::id());
        std::fs::write(dir.join(&own), b"booted 1").unwrap();
        std::fs::create_dir_all(dir.join("svc-db/.build-2-0-y")).unwrap();

        // Fresh, the files are left: a build may be about to rename or read them.
        let mut got = Collected::default();
        collect_in(&dir, false, SystemTime::now(), &mut got);
        assert!(
            !dir.join(".build-1-0-x").exists(),
            "an abandoned scratch goes at once"
        );
        assert!(!dir.join("svc-db/.build-2-0-y").exists(), "a service's too");
        assert!(
            dir.join("root.qcow2.tmp").exists(),
            "a fresh export is left"
        );
        assert_eq!(got.dirs, 1);

        let later = SystemTime::now() + GRACE + Duration::from_secs(1);
        let mut dry = Collected::default();
        collect_in(&dir, true, later, &mut dry);
        assert_eq!(dry.dirs, 1);
        assert!(
            dir.join("root.qcow2.tmp").exists(),
            "a dry run removes nothing"
        );

        let mut got = Collected::default();
        collect_in(&dir, false, later, &mut got);
        assert_eq!(got, dry, "a dry run counts what a pass removes");
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let mut want = vec![
            own,
            "dev.json".to_string(),
            "id_ed25519".into(),
            "root.qcow2".into(),
            "root.qcow2.json".into(),
            "roots".into(),
            "svc-db".into(),
        ];
        want.sort();
        assert_eq!(left, want, "a live parent's note and everything else stay");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_settled_throwaway_dir_goes_whole_and_a_held_one_stays() {
        let dir = scratch("throwaway");
        std::fs::write(dir.join(crate::dev::task::THROWAWAY_MARKER), b"").unwrap();
        std::fs::write(dir.join("root.qcow2"), b"x").unwrap();

        let mut got = Collected::default();
        collect_in(&dir, false, SystemTime::now(), &mut got);
        assert!(dir.exists(), "one made moments ago may be about to boot");

        let later = SystemTime::now() + GRACE + Duration::from_secs(1);
        let held = crate::dev::list::try_lock_state_dir(&dir).unwrap();
        collect_in(&dir, false, later, &mut got);
        assert!(dir.exists(), "a dir a run holds is left");
        assert_eq!(got, Collected::default());
        drop(held);

        collect_in(&dir, false, later, &mut got);
        assert!(!dir.exists());
        assert_eq!(got.dirs, 1);
    }
}
