//! A placed job's directory, `<state_dir>/node/jobs/<hub job id>/` (`0700`). The session
//! (`vk node run`) writes the hub's requests; the driver (`vk node job`) writes the outcomes.
//! Both processes run as this user, so journal reads cross no trust boundary.
//!
//! - `start.json` (`0600`): the [`JobStart`], secrets and all, written before the job is
//!   accepted, so a start redelivered after a reconnect is recognized;
//! - `meta.json`: the GitLab job ID and the slots the session gave the job;
//! - `driver.pid`: the driver's pid, written by the session and by the driver itself;
//! - `output`: the trace, as the hub receives it;
//! - `stage`: the stage the driver is in;
//! - `cancel`: `graceful` or `immediate`, written by the session;
//! - `result.json`: how the job ended, written last by the driver;
//! - `scripts/`, `scratch/`: the driver's own.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vk_hub_proto::dispatch::{CancelMode, JobStart};
use vk_hub_proto::job::JobResult;

pub const START: &str = "start.json";
pub const META: &str = "meta.json";
pub const PID: &str = "driver.pid";
pub const OUTPUT: &str = "output";
pub const STAGE: &str = "stage";
pub const CANCEL: &str = "cancel";
pub const RESULT: &str = "result.json";
pub const DRIVER_LOG: &str = "driver.log";

/// What the session decided for a job when it took it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub gitlab_id: u64,
    /// `CI_CONCURRENT_ID`.
    pub slot: u32,
    /// `CI_CONCURRENT_PROJECT_ID`.
    pub project_slot: u32,
    pub project_id: u64,
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encoding the job journal")?;
    vk_fs::write_atomic(path, &bytes, 0o600).with_context(|| format!("writing {}", path.display()))
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))
}

pub fn read_start(dir: &Path) -> Result<JobStart> {
    read_json(&dir.join(START))
}

pub fn read_meta(dir: &Path) -> Result<Meta> {
    read_json(&dir.join(META))
}

/// The result, once the driver has written it.
pub fn read_result(dir: &Path) -> Option<JobResult> {
    read_json(&dir.join(RESULT)).ok()
}

pub fn read_stage(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(STAGE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn read_cancel(dir: &Path) -> Option<CancelMode> {
    match std::fs::read_to_string(dir.join(CANCEL)).ok()?.trim() {
        "immediate" => Some(CancelMode::Immediate),
        "graceful" => Some(CancelMode::Graceful),
        _ => None,
    }
}

/// Ask for a cancel; a graceful one never downgrades an immediate one.
pub fn write_cancel(dir: &Path, mode: CancelMode) -> Result<()> {
    if read_cancel(dir) == Some(CancelMode::Immediate) {
        return Ok(());
    }
    let word = match mode {
        CancelMode::Graceful => "graceful",
        CancelMode::Immediate | CancelMode::Other => "immediate",
    };
    vk_fs::write_atomic(&dir.join(CANCEL), word.as_bytes(), 0o600)
}

/// The output's length so far.
pub fn output_len(dir: &Path) -> u64 {
    std::fs::metadata(dir.join(OUTPUT)).map_or(0, |m| m.len())
}

/// The driver's pid, while that pid is still the driver of `dir`: its command line names
/// the dir, canonical as the session spells it to the driver, which a recycled pid's does not.
pub fn live_driver(dir: &Path) -> Option<i32> {
    let dir = dir.canonicalize().ok()?;
    let pid: i32 = std::fs::read_to_string(dir.join(PID))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let want = dir.as_os_str().as_encoded_bytes();
    cmdline
        .split(|&b| b == 0)
        .any(|arg| arg == want)
        .then_some(pid)
}

pub fn scripts_dir(dir: &Path) -> PathBuf {
    dir.join("scripts")
}

pub fn scratch_dir(dir: &Path) -> PathBuf {
    dir.join("scratch")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancel_never_downgrades() {
        let dir = std::env::temp_dir().join(format!("vk-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_cancel(&dir), None);
        write_cancel(&dir, CancelMode::Graceful).unwrap();
        assert_eq!(read_cancel(&dir), Some(CancelMode::Graceful));
        write_cancel(&dir, CancelMode::Immediate).unwrap();
        write_cancel(&dir, CancelMode::Graceful).unwrap();
        assert_eq!(read_cancel(&dir), Some(CancelMode::Immediate));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_driver_is_found_whatever_the_dirs_spelling() {
        let base = std::env::temp_dir().join(format!("vk-journal-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("jobs").join("j");
        std::fs::create_dir_all(&dir).unwrap();
        let canonical = dir.canonicalize().unwrap();
        // A process whose command line names the canonical dir, as the driver's does.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30; :", "driver"])
            .arg(&canonical)
            .spawn()
            .unwrap();
        std::fs::write(dir.join(PID), child.id().to_string()).unwrap();
        let other_spelling = base.join("jobs/../jobs/./j");
        // Its command line can read empty right after the spawn.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while live_driver(&other_spelling).is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            live_driver(&other_spelling),
            Some(child.id() as i32),
            "found through {}",
            other_spelling.display()
        );
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(live_driver(&dir), None, "gone once it exits");
        let _ = std::fs::remove_dir_all(&base);
    }
}
