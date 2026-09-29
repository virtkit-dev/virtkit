//! Whether the job has a gitlab-runner, for the host's job trace.
//!
//! Without gitlab-runner the runner's helper steps transfer no artifacts, caches or dotenv
//! reports, and the job still passes. PID 1 links the `[executor] tools_dir` share's tools
//! onto PATH (`init`); when neither that share nor the image leaves the job a gitlab-runner,
//! it records the share's reason in [`PROBLEM`] on the agent's `/run` tmpfs, and the host
//! reads it back through `vk-agent tools` during prepare. Only the guest can decide, since
//! only it knows what the image ships.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use log::warn;

/// Why the CI tools share left the job without gitlab-runner; absent when the job has one.
const PROBLEM: &str = "/run/vk-tools-problem";

/// The share's gitlab-runner, as init's scan of the share found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SharedRunner {
    Absent,
    /// Not [`runnable`], as the host's `vk check` also requires.
    Unusable,
    LinkFailed(String),
    Linked,
}

/// What a readable share held: whether it had any entry, and its gitlab-runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolsScan {
    pub(crate) empty: bool,
    pub(crate) runner: SharedRunner,
}

/// Whether `path` is an executable regular file once links are followed, as exec will.
pub(crate) fn runnable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Why the job has no gitlab-runner, given the share's scan (or why it could not be read) and
/// whether the image ships one; `None` when the job has one.
pub(crate) fn problem(scan: &Result<ToolsScan, String>, image_has_runner: bool) -> Option<String> {
    if image_has_runner {
        return None;
    }
    let scan = match scan {
        Ok(scan) => scan,
        Err(why) => return Some(why.clone()),
    };
    match &scan.runner {
        SharedRunner::Linked => None,
        SharedRunner::Absent if scan.empty => Some("the share is empty".into()),
        SharedRunner::Absent => Some("the share has no gitlab-runner".into()),
        SharedRunner::Unusable => {
            Some("the share's gitlab-runner is not an executable file the guest can reach".into())
        }
        SharedRunner::LinkFailed(e) => Some(format!("linking the share's gitlab-runner: {e}")),
    }
}

/// Record `why` for [`main`]. Only on our own `/run`, created exclusively: never into the
/// image, nor over a file it ships.
pub(crate) fn record(why: &str) {
    if !crate::memmark::is_own_mount(Path::new("/run")) {
        return;
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(PROBLEM)
        .and_then(|mut f| f.write_all(format!("{why}\n").as_bytes()));
    if let Err(e) = written {
        warn!("vk-agent init: recording the CI tools problem in {PROBLEM}: {e}");
    }
}

/// `vk-agent tools`: print why the CI tools share left this guest without gitlab-runner, or
/// nothing when it did not (or when the guest was booted without one). Only our own `/run`
/// is read, so a file the image ships is never reported.
pub fn main(args: &[String]) -> i32 {
    if !args.is_empty() {
        eprintln!("usage: vk-agent tools");
        return 2;
    }
    if !crate::memmark::is_own_mount(Path::new("/run")) {
        return 0;
    }
    let why = match std::fs::read(PROBLEM) {
        Ok(why) => why,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            eprintln!("tools: reading {PROBLEM}: {e}");
            return 1;
        }
    };
    let mut out = std::io::stdout().lock();
    match out.write_all(&why).and_then(|()| out.flush()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("tools: writing the problem: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job with gitlab-runner, from the image or the share, reports nothing; one without it
    /// reports the share's reason.
    #[test]
    fn only_a_job_without_gitlab_runner_has_a_problem() {
        let scan = |empty, runner| Ok(ToolsScan { empty, runner });
        let failed: Result<ToolsScan, String> = Err("the share cannot be mounted: ENODEV".into());
        let every = [
            failed.clone(),
            scan(true, SharedRunner::Absent),
            scan(false, SharedRunner::Absent),
            scan(false, SharedRunner::Unusable),
            scan(false, SharedRunner::LinkFailed("EEXIST".into())),
            scan(false, SharedRunner::Linked),
        ];
        for s in &every {
            assert_eq!(problem(s, true), None, "{s:?}");
        }
        let why = |s: &Result<ToolsScan, String>| problem(s, false);
        assert_eq!(
            why(&failed).as_deref(),
            Some("the share cannot be mounted: ENODEV")
        );
        assert_eq!(
            why(&scan(true, SharedRunner::Absent)).as_deref(),
            Some("the share is empty")
        );
        assert_eq!(
            why(&scan(false, SharedRunner::Absent)).as_deref(),
            Some("the share has no gitlab-runner")
        );
        assert_eq!(
            why(&scan(false, SharedRunner::Unusable)).as_deref(),
            Some("the share's gitlab-runner is not an executable file the guest can reach")
        );
        assert_eq!(
            why(&scan(false, SharedRunner::LinkFailed("EEXIST".into()))).as_deref(),
            Some("linking the share's gitlab-runner: EEXIST")
        );
        assert_eq!(why(&scan(false, SharedRunner::Linked)), None);
    }

    /// Only an executable regular file counts, links followed.
    #[test]
    fn runnable_is_an_executable_regular_file() {
        let dir = std::env::temp_dir().join(format!("vk-tools-runnable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let file = |name: &str, mode| {
            let p = dir.join(name);
            std::fs::write(&p, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        let exe = file("exe", 0o755);
        let plain = file("plain", 0o644);
        std::os::unix::fs::symlink(&exe, dir.join("to-exe")).unwrap();
        std::os::unix::fs::symlink(&plain, dir.join("to-plain")).unwrap();
        std::os::unix::fs::symlink(dir.join("gone"), dir.join("dangling")).unwrap();
        assert!(runnable(&exe));
        assert!(runnable(&dir.join("to-exe")));
        assert!(!runnable(&plain));
        assert!(!runnable(&dir.join("to-plain")));
        assert!(!runnable(&dir.join("dangling")));
        assert!(!runnable(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
